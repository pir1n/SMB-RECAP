from collections import defaultdict

from smbmount.scf.fingerprint import (
    fingerprint_packet,
    fingerprint_sequence,
    packet_signatures,
)
from smbmount.scf.normalize import canonical_value
from smbmount.scf.directory_tracker import DirectoryTracker
from smbmount.scf.handle_tracker import HandleTracker


class SCFDetector:

    def __init__(
        self,
        rules,
        include_tree_ids=None,
        exclude_tree_ids=None,
        include_session_trees=None,
        exclude_session_trees=None,
    ):
        self.rules = rules
        self.include_tree_ids = {
            str(value) for value in (include_tree_ids or [])
        }
        self.exclude_tree_ids = {
            str(value) for value in (exclude_tree_ids or [])
        }
        self.include_session_trees = {
            (str(session_id), str(tree_id))
            for session_id, tree_id in (include_session_trees or [])
        }
        self.exclude_session_trees = {
            (str(session_id), str(tree_id))
            for session_id, tree_id in (exclude_session_trees or [])
        }

    def _tree_is_in_scope(self, packet):
        """Apply an explicit SMB tree scope without guessing from paths.

        A capture can contain the experiment share together with SYSVOL,
        NETLOGON, DFS or other background SMB trees. TreeId is assigned by the
        SMB server and is therefore a protocol-level boundary, unlike path
        prefixes learned from one evaluation capture.
        """
        session_id = packet.get("smb2_session_id")
        session_id = None if session_id is None else str(session_id)
        tree_id = packet.get("smb2_tree_id")
        tree_id = None if tree_id is None else str(tree_id)
        session_tree = (session_id, tree_id)
        if self.include_session_trees and session_tree not in self.include_session_trees:
            return False
        if session_tree in self.exclude_session_trees:
            return False
        if self.include_tree_ids and tree_id not in self.include_tree_ids:
            return False
        if tree_id in self.exclude_tree_ids:
            return False
        return True

    def detect(self, packets, progress_callback=None):
        packets = [packet for packet in packets if self._tree_is_in_scope(packet)]
        events = []

        handle_tracker = HandleTracker()
        handle_tracker.track(packets)
        self.completed_states = handle_tracker.completed_operations()
        directory_tracker = DirectoryTracker()
        directory_tracker.track(packets)
        self.completed_enumerations = directory_tracker.completed_enumerations()

        status_lookup = self._build_response_status_lookup(packets)
        groups = self._group_requests(packets)
        total_positions = sum(len(requests) for requests in groups.values())
        processed_positions = 0
        next_progress = 10

        # Prefer longer rules first so short rules do not consume a longer match.
        sorted_rules = sorted(
            self.rules,
            key=lambda r: len(r.get("pattern", [])),
            reverse=True,
        )

        if progress_callback and total_positions == 0:
            progress_callback(100)

        for group_key, requests in groups.items():
            requests = sorted(
                requests,
                key=lambda p: (
                    p.get("timestamp") or 0,
                    p.get("frame_number") or 0,
                )
            )

            packet_hashes = [fingerprint_packet(pkt) for pkt in requests]
            packet_signatures_list = packet_signatures(requests)

            for i in range(len(requests)):
                for rule in sorted_rules:
                    match = self._match_rule(
                        rule=rule,
                        requests=requests,
                        packet_hashes=packet_hashes,
                        packet_signatures_list=packet_signatures_list,
                        start=i,
                        status_lookup=status_lookup,
                    )

                    if not match:
                        continue

                    seq = match["seq"]
                    statuses = match["statuses"]

                    events.append({
                        "timestamp": self.safe_float(seq[0].get("timestamp")),
                        "src_ip": seq[0].get("src_ip"),
                        "dst_ip": seq[0].get("dst_ip"),
                        "src_port": seq[0].get("src_port"),
                        "dst_port": seq[0].get("dst_port"),
                        "session_id": seq[0].get("smb2_session_id"),
                        "tree_id": seq[0].get("smb2_tree_id"),

                        "rule_id": rule.get("id"),
                        "action": rule.get("action"),
                        "description": rule.get("description"),

                        "path": self.extract_path(seq),
                        "target_path": self.extract_target_path(seq),
                        "file_id": self.extract_file_id(seq),
                        "handle_generation": seq[0].get("handle_generation"),
                        "operation_state_id": seq[0].get("operation_state_id"),

                        "query_entry_count": self._sequence_last_value(seq, "smb2_query_entry_count"),
                        "query_returned_names": self._sequence_last_value(seq, "smb2_query_aggregate_returned_names") or self._sequence_last_value(seq, "smb2_query_returned_names"),
                        "query_page_index": self._sequence_last_value(seq, "smb2_query_page_index"),
                        "query_end_of_search": self._sequence_last_value(seq, "smb2_query_end_of_search"),
                        "query_response_status": self._sequence_last_value(seq, "smb2_query_response_status"),
                        "query_total_bytes": self._sequence_last_value(seq, "smb2_query_aggregate_total_bytes") or self._sequence_last_value(seq, "smb2_query_total_bytes"),

                        "frames": [p.get("frame_number") for p in seq],
                        "commands": [p.get("smb2_command_name") for p in seq],
                        "packet_scfs": match["packet_scfs"],
                        "normalized_scfs": match["normalized_scfs"],
                        "features": match["features"],
                        "sequence_scf": fingerprint_sequence(seq),

                        "statuses": statuses,
                        "success": self._sequence_success(statuses),
                        "confidence": rule.get("confidence", 1.0),
                    })

                    # The longest rule at this position is enough.
                    break

                processed_positions += 1
                if progress_callback and total_positions:
                    percent = int((processed_positions * 100) / total_positions)
                    while percent >= next_progress and next_progress <= 100:
                        progress_callback(next_progress)
                        next_progress += 10

        return self._post_process_events(events)

    def _match_rule(self, rule, requests, packet_hashes, packet_signatures_list, start, status_lookup):
        # New rule mode: match SCF/hash/normalized/object pattern entries.
        if "pattern" in rule:
            pattern = rule["pattern"]
            indices = self._match_pattern_indices(
                pattern=pattern,
                signatures=packet_signatures_list,
                start=start,
                max_gap=rule.get("max_gap", 0),
            )

            if indices is None:
                return None

            seq = [requests[idx] for idx in indices]

            # `same_file_id: false` permits rules to operate when a dissector
            # cannot recover every handle.  It must not permit a sequence that
            # positively contains two different FileIds: those commands are
            # known to address different SMB opens.
            if self._sequence_has_conflicting_file_ids(seq):
                return None

            # A session/tree may use several TCP transports with SMB 3
            # Multichannel.  Crossing a transport boundary is valid only when
            # the commands refer to the same server-issued file handle.  This
            # prevents an unrelated CREATE on channel A from being paired with
            # SET_INFO/QUERY_DIRECTORY on channel B merely because a rule opts
            # out of its ordinary same_file_id check.
            if (
                self._sequence_crosses_transport_channels(seq)
                and not self._sequence_same_file_id(seq)
            ):
                return None

            statuses = self._statuses_for_sequence(seq, status_lookup)

            if rule.get("require_success") and self._sequence_success(statuses) is False:
                return None

            if rule.get("require_path") and not self.extract_path(seq):
                return None

            same_file_id = rule.get("same_file_id")
            if same_file_id is None:
                same_file_id = len(pattern) > 1
            if same_file_id and not self._sequence_same_file_id(seq):
                return None

            return {
                "seq": seq,
                "statuses": statuses,
                "packet_scfs": [packet_signatures_list[idx]["scf"] for idx in indices],
                "normalized_scfs": [packet_signatures_list[idx]["normalized"] for idx in indices],
                "features": [packet_signatures_list[idx]["features"] for idx in indices],
            }

        # Legacy rule: match sequence hash
        if "hash" in rule:
            max_size = min(8, len(requests) - start)

            for size in range(1, max_size + 1):
                seq = requests[start:start + size]
                fp = fingerprint_sequence(seq)

                if fp != rule["hash"]:
                    continue

                statuses = self._statuses_for_sequence(seq, status_lookup)

                if rule.get("require_success") and self._sequence_success(statuses) is False:
                    return None

                return {
                    "seq": seq,
                    "statuses": statuses,
                    "packet_scfs": packet_hashes[start:start + size],
                    "normalized_scfs": [
                        packet_signatures_list[idx]["normalized"]
                        for idx in range(start, start + size)
                    ],
                    "features": [
                        packet_signatures_list[idx]["features"]
                        for idx in range(start, start + size)
                    ],
                }

        return None

    def _match_pattern_indices(self, pattern, signatures, start, max_gap=0):
        if start >= len(signatures):
            return None

        if not self._match_pattern_item(pattern[0], signatures[start]):
            return None

        indices = [start]
        cursor = start + 1

        for pattern_item in pattern[1:]:
            found = None
            search_end = min(len(signatures), cursor + max_gap + 1)

            for idx in range(cursor, search_end):
                if self._match_pattern_item(pattern_item, signatures[idx]):
                    found = idx
                    break

            if found is None:
                return None

            indices.append(found)
            cursor = found + 1

        return indices

    def _match_pattern_item(self, pattern_item, signature):
        if isinstance(pattern_item, str):
            return pattern_item in (
                signature["scf"],
                signature["normalized"],
                signature["features"].get("command"),
            )

        if not isinstance(pattern_item, dict):
            return False

        features = signature["features"]

        if pattern_item.get("scf") and pattern_item["scf"] != signature["scf"]:
            return False

        if pattern_item.get("normalized") and pattern_item["normalized"] != signature["normalized"]:
            return False

        if pattern_item.get("command") and pattern_item["command"] != features.get("command"):
            return False

        for key, expected in pattern_item.get("features", {}).items():
            if canonical_value(features.get(key)) != canonical_value(expected):
                return False

        for key, choices in pattern_item.get("any_features", {}).items():
            if not isinstance(choices, (list, tuple, set)):
                choices = [choices]
            actual = canonical_value(features.get(key))
            if actual not in {canonical_value(choice) for choice in choices}:
                return False

        for key, expected_values in pattern_item.get("contains", {}).items():
            actual_values = features.get(key) or []
            if not isinstance(actual_values, (list, tuple, set)):
                actual_values = [actual_values]
            actual_set = {canonical_value(value) for value in actual_values}
            expected_set = {canonical_value(value) for value in expected_values}
            if not expected_set.issubset(actual_set):
                return False

        return True

    def _post_process_events(self, events):
        events = sorted(
            events,
            key=lambda e: (
                self.safe_float(e.get("timestamp")) or 0,
                e.get("frames", [0])[0] if e.get("frames") else 0,
            ),
        )
        events = self._suppress_subsumed_events(events)
        events = self._merge_duplicate_bursts(events)
        events = self._suppress_duplicate_download_phases(events)
        events = self._suppress_subordinate_download_reads(events)
        events = self._suppress_subordinate_directory_listings(events)
        events = self._suppress_subordinate_io(events)
        return events

    def _suppress_subsumed_events(self, events):
        """Drop a short rule hit already represented by a longer rule hit.

        Custom and builtin rules can both identify the same operation.  For
        example, CREATE->SET_INFO rename and a SET_INFO-only fallback share the
        same terminal frame.  Keeping both turns one real operation into a TP
        plus an FP during evaluation.
        """
        suppressed = set()

        for idx, event in enumerate(events):
            frames = {frame for frame in event.get("frames", []) if frame is not None}
            if not frames:
                continue

            family = self._event_family(event)
            for other_idx, other in enumerate(events):
                if other_idx == idx or self._event_family(other) != family:
                    continue
                other_frames = {
                    frame for frame in other.get("frames", []) if frame is not None
                }
                if frames < other_frames:
                    suppressed.add(idx)
                    break

        return [
            event
            for idx, event in enumerate(events)
            if idx not in suppressed
        ]

    def _event_family(self, event):
        text = f"{event.get('action') or ''} {event.get('rule_id') or ''}".lower()
        for family in (
            "rename",
            "delete",
            "directory listing",
            "download",
            "upload",
            "append",
            "overwrite",
            "read",
            "write",
            "creation",
        ):
            if family in text:
                return family
        return text

    def _merge_duplicate_bursts(self, events, window=0.25):
        merged = []
        buckets = {}

        for event in events:
            key = self._dedup_key(event)
            ts = self.safe_float(event.get("timestamp"))
            bucket = None if ts is None else int(ts / window)
            # Repeated explicit `dir` commands can legitimately occur within
            # 250 ms.  Merge only duplicate parser hits for the same listing
            # frames, not distinct QUERY_DIRECTORY operations in one bucket.
            listing_frames = (
                tuple(event.get("frames", []))
                if self._is_directory_listing_event(event)
                else None
            )
            bucket_key = (key, bucket, listing_frames)
            candidate = buckets.get(bucket_key)

            if candidate is None:
                event["_dedup_key"] = key
                merged.append(event)
                buckets[bucket_key] = event
                continue

            candidate["frames"] = self._unique_extend(candidate.get("frames", []), event.get("frames", []))
            candidate["commands"] = self._unique_extend(candidate.get("commands", []), event.get("commands", []))
            candidate["packet_scfs"] = self._unique_extend(candidate.get("packet_scfs", []), event.get("packet_scfs", []))
            candidate["normalized_scfs"] = self._unique_extend(candidate.get("normalized_scfs", []), event.get("normalized_scfs", []))
            candidate["features"] = candidate.get("features", []) + event.get("features", [])
            candidate["statuses"] = candidate.get("statuses", []) + event.get("statuses", [])
            candidate["success"] = self._sequence_success(candidate.get("statuses", []))

        for event in merged:
            event.pop("_dedup_key", None)

        return merged

    def _suppress_duplicate_download_phases(self, events, window=0.25):
        """Collapse the two rule hits emitted by one buffered CMD download.

        A CMD ``copy`` from the share can open and read the same source through
        a buffered handle and then a regular handle.  The two fingerprints are
        useful for coverage, but together represent one user-level operation.
        Restrict suppression to the known ordered rule pair, same path, and a
        short time window so independent downloads remain distinct.
        """
        suppressed = set()

        for idx, event in enumerate(events):
            if event.get("rule_id") != "cmd_copy_download_file_buffered":
                continue

            path = self._canonical_path(event.get("path"))
            timestamp = self.safe_float(event.get("timestamp"))
            if not path or timestamp is None:
                continue

            for other_idx in range(idx + 1, len(events)):
                other = events[other_idx]
                other_timestamp = self.safe_float(other.get("timestamp"))
                if other_timestamp is None:
                    continue
                if other_timestamp - timestamp > window:
                    break
                if other.get("rule_id") != "cmd_copy_download_file":
                    continue
                if self._canonical_path(other.get("path")) != path:
                    continue

                suppressed.add(other_idx)
                break

        return [
            event
            for idx, event in enumerate(events)
            if idx not in suppressed
        ]

    def _suppress_subordinate_io(self, events, window=0.75):
        suppressed = set()

        for idx, event in enumerate(events):
            if event.get("rule_id") != "overwrite_file":
                continue

            ts = self.safe_float(event.get("timestamp"))
            path = self._canonical_path(event.get("path"))
            if ts is None or not path:
                continue

            for other_idx, other in enumerate(events):
                if other_idx == idx or other_idx in suppressed:
                    continue
                if other.get("rule_id") != "write_file":
                    continue
                if self._canonical_path(other.get("path")) != path:
                    continue
                other_ts = self.safe_float(other.get("timestamp"))
                if other_ts is not None and 0 <= other_ts - ts <= window:
                    suppressed.add(other_idx)

        return [
            event
            for idx, event in enumerate(events)
            if idx not in suppressed
        ]

    def _suppress_subordinate_directory_listings(self, events, window=1.0):
        suppressed = set()

        for idx, event in enumerate(events):
            if not self._is_directory_listing_event(event):
                continue

            path = self._canonical_path(event.get("path"))
            ts = self.safe_float(event.get("timestamp"))

            # A shallow path may be an explicit `dir` target.  Do not discard
            # it solely because it is the share/run root.  Support-command
            # suppression below requires contextual evidence from a nearby
            # rename/delete instead of path depth.

            if ts is None:
                continue

            # Windows may first enumerate the share root to resolve a child
            # target, then enumerate that target a few milliseconds later.
            # The parent page is protocol support, not a second `dir` action.
            if not path:
                returned_names = {
                    str(name).lower()
                    for name in event.get("query_returned_names") or []
                }
                for other_idx, other in enumerate(events):
                    if other_idx == idx or not self._is_directory_listing_event(other):
                        continue
                    other_ts = self.safe_float(other.get("timestamp"))
                    other_path = self._canonical_path(other.get("path"))
                    if other_ts is None or not other_path:
                        continue
                    if not (0 <= other_ts - ts <= 0.25):
                        continue
                    if other_path.rsplit("/", 1)[-1] in returned_names:
                        suppressed.add(idx)
                        break
                continue

            for other_idx, other in enumerate(events):
                if other_idx == idx:
                    continue
                if not self._is_mutating_event(other):
                    continue

                other_ts = self.safe_float(other.get("timestamp"))
                if other_ts is None or not (0 <= other_ts - ts <= window):
                    continue

                other_path = self._canonical_path(other.get("path"))
                other_target = self._canonical_path(other.get("target_path"))
                related_paths = {value for value in (other_path, other_target) if value}
                same_object = path in related_paths
                child_object = (
                    len(path.split("/")) > 1
                    and any(value.startswith(path + "/") for value in related_paths)
                )
                direct_child = any(
                    value.rsplit("/", 1)[0] == path
                    for value in related_paths
                    if "/" in value
                )
                returned_names = {
                    str(name).lower()
                    for name in event.get("query_returned_names") or []
                }
                empty_enumeration = bool(returned_names) and returned_names <= {".", ".."}
                protocol_support_probe = empty_enumeration and direct_child
                if same_object or (
                    child_object
                    and (self._is_rename_event(other) or self._is_delete_event(other))
                ) or protocol_support_probe:
                    suppressed.add(idx)
                    break

        return [
            event
            for idx, event in enumerate(events)
            if idx not in suppressed
        ]

    def _suppress_subordinate_download_reads(self, events, window=0.75):
        suppressed = set()

        downloads = []
        for idx, event in enumerate(events):
            if self._is_download_event(event):
                downloads.append((idx, event))

        for idx, event in enumerate(events):
            if not self._is_read_event(event):
                continue

            read_path = self._canonical_path(event.get("path"))
            read_ts = self.safe_float(event.get("timestamp"))

            if read_ts is None or not read_path:
                continue

            for download_idx, download in downloads:
                if download_idx == idx:
                    continue

                download_path = self._canonical_path(
                    download.get("path")
                )
                if download_path != read_path:
                    continue

                download_ts = self.safe_float(
                    download.get("timestamp")
                )
                if download_ts is None:
                    continue

                # Time chỉ dùng để thu hẹp candidate.
                # Không dùng path + time làm bằng chứng suppress cuối cùng.
                if abs(download_ts - read_ts) > window:
                    continue

                read_file_id = event.get("file_id")
                download_file_id = download.get("file_id")

                same_handle = (
                    read_file_id is not None
                    and download_file_id is not None
                    and str(read_file_id) == str(download_file_id)
                )

                read_frames = {
                    frame
                    for frame in event.get("frames", [])
                    if frame is not None
                }
                download_frames = {
                    frame
                    for frame in download.get("frames", [])
                    if frame is not None
                }

                shared_frame = bool(
                    read_frames.intersection(download_frames)
                )

                # Chỉ suppress khi có bằng chứng hai detection
                # thực sự mô tả cùng SMB operation.
                if same_handle or shared_frame:
                    suppressed.add(idx)
                    break

        return [
            event
            for idx, event in enumerate(events)
            if idx not in suppressed
        ]

    def _is_directory_listing_event(self, event):
        return "directory listing" in str(event.get("action") or "").lower()

    def _is_download_event(self, event):
        text = f"{event.get('action') or ''} {event.get('rule_id') or ''}".lower()
        return "download" in text

    def _is_read_event(self, event):
        action = str(event.get("action") or "").lower()
        rule_id = str(event.get("rule_id") or "").lower()
        return ("read of file" in action or "read_file" in rule_id) and not self._is_download_event(event)

    def _is_rename_event(self, event):
        action = str(event.get("action") or "").lower()
        return "rename" in action or "move" in action

    def _is_delete_event(self, event):
        return "deletion" in str(event.get("action") or "").lower()

    def _is_mutating_event(self, event):
        text = f"{event.get('action') or ''} {event.get('rule_id') or ''}".lower()
        return any(token in text for token in (
            "creation", "create_", "upload", "append", "overwrite",
            "write", "rename", "move", "deletion", "delete_",
        ))

    def _dedup_key(self, event):
        return (
            event.get("rule_id"),
            self._canonical_path(event.get("path")),
            self._canonical_path(event.get("target_path")),
        )

    def _sequence_same_file_id(self, seq):
        file_ids = []
        for pkt in seq:
            fid = pkt.get("smb2_file_id") or pkt.get("mapped_file_id")
            if fid is None:
                return False
            if isinstance(fid, bytes):
                fid = fid.hex()
            file_ids.append(str(fid))
        return len(set(file_ids)) == 1

    def _sequence_has_conflicting_file_ids(self, seq):
        file_ids = set()
        for pkt in seq:
            fid = pkt.get("smb2_file_id") or pkt.get("mapped_file_id")
            if fid is None:
                continue
            if isinstance(fid, bytes):
                fid = fid.hex()
            file_ids.add(str(fid))
        return len(file_ids) > 1

    def _sequence_crosses_transport_channels(self, seq):
        channels = {
            (
                pkt.get("src_ip"),
                pkt.get("dst_ip"),
                pkt.get("src_port"),
                pkt.get("dst_port"),
            )
            for pkt in seq
        }
        return len(channels) > 1

    def _canonical_path(self, path):
        if path is None:
            return None
        return str(path).replace("\\", "/").strip("/").lower()

    def _unique_extend(self, left, right):
        output = list(left or [])
        for item in right or []:
            if item not in output:
                output.append(item)
        return output

    def _group_requests(self, packets):
        groups = defaultdict(list)

        for pkt in packets:
            if pkt.get("smb2_is_response") is not False:
                continue

            key = self._request_group_key(pkt)
            groups[key].append(pkt)

        return groups

    def _request_group_key(self, pkt):
        # SMB 3 Multichannel can distribute commands from one logical tree
        # connection over several TCP connections.  FileId is the SMB-layer
        # handle that safely joins CREATE with READ/WRITE/SET_INFO across those
        # channels.  SessionId + TreeId alone is too broad because one tree can
        # have many concurrent file operations.
        #
        # Ports deliberately remain part of _request_response_key(): request
        # and response correlation by MessageId is transport-channel scoped.
        state_id = pkt.get("operation_state_id")
        if state_id is not None:
            return ("operation-state",) + tuple(state_id)

        file_id = pkt.get("smb2_file_id") or pkt.get("mapped_file_id")
        if isinstance(file_id, bytes):
            file_id = file_id.hex()

        if file_id is not None:
            return (
                "smb-handle",
                pkt.get("src_ip"),
                pkt.get("dst_ip"),
                pkt.get("smb2_session_id"),
                pkt.get("smb2_tree_id"),
                str(file_id),
            )

        # Some commands do not carry a FileId.  Do not merge those commands
        # across channels without a protocol-level correlation identifier.
        return (
            "transport",
            pkt.get("src_ip"),
            pkt.get("dst_ip"),
            pkt.get("src_port"),
            pkt.get("dst_port"),
            pkt.get("smb2_session_id"),
            pkt.get("smb2_tree_id"),
        )

    @staticmethod
    def _sequence_last_value(seq, field):
        for packet in reversed(seq):
            value = packet.get(field)
            if value is not None:
                return value
        return None

    def _request_response_key(self, pkt):
        return (
            pkt.get("src_ip"),
            pkt.get("dst_ip"),
            pkt.get("src_port"),
            pkt.get("dst_port"),
            pkt.get("smb2_session_id"),
            pkt.get("smb2_tree_id"),
            pkt.get("smb2_message_id"),
            pkt.get("smb2_command_name"),
        )

    def _response_to_request_key(self, pkt):
        # Response travels in the opposite direction, so invert src/dst and ports.
        return (
            pkt.get("dst_ip"),
            pkt.get("src_ip"),
            pkt.get("dst_port"),
            pkt.get("src_port"),
            pkt.get("smb2_session_id"),
            pkt.get("smb2_tree_id"),
            pkt.get("smb2_message_id"),
            pkt.get("smb2_command_name"),
        )

    def _build_response_status_lookup(self, packets):
        lookup = {}

        for pkt in packets:
            if pkt.get("smb2_is_response") is not True:
                continue

            key = self._response_to_request_key(pkt)
            lookup[key] = pkt.get("smb2_status")

        return lookup

    def _statuses_for_sequence(self, seq, status_lookup):
        statuses = []

        for pkt in seq:
            key = self._request_response_key(pkt)
            statuses.append(status_lookup.get(key))

        return statuses

    def _sequence_success(self, statuses):
        if not statuses:
            return None

        # If no response can be matched, success is unknown.
        if all(s is None for s in statuses):
            return None

        return all(self._status_success(s) for s in statuses if s is not None)

    def _status_success(self, status):
        if status is None:
            return False

        if isinstance(status, int):
            return status == 0

        text = str(status).strip()

        if text in ("0", "0x0", "0x00000000", "STATUS_SUCCESS"):
            return True

        try:
            return int(text, 0) == 0
        except Exception:
            return False

    def safe_float(self, value):
        if value is None:
            return None

        try:
            return float(value)
        except Exception:
            return None

    def extract_path(self, seq):
        for pkt in seq:
            if pkt.get("smb2_filename"):
                return pkt["smb2_filename"]

            if pkt.get("mapped_filename"):
                return pkt["mapped_filename"]

        return None

    def extract_target_path(self, seq):
        for pkt in seq:
            if pkt.get("smb2_rename_target"):
                return pkt["smb2_rename_target"]

        return None

    def extract_file_id(self, seq):
        for pkt in seq:
            if pkt.get("smb2_file_id"):
                fid = pkt["smb2_file_id"]
                return fid.hex() if isinstance(fid, bytes) else fid

            if pkt.get("mapped_file_id"):
                fid = pkt["mapped_file_id"]
                return fid.hex() if isinstance(fid, bytes) else fid

        return None
    
    # Detect delete-on-close events
    
    def is_delete_on_close_create(self, pkt):
        if pkt.get("smb2_command_name") != "CREATE":
            return False

        if pkt.get("smb2_is_response") is not False:
            return False

        desired = pkt.get("smb2_desired_access_raw") or 0
        options = pkt.get("smb2_create_options_raw") or 0

        try:
            desired = int(desired)
            options = int(options)
        except Exception:
            return False

        DELETE_ACCESS = 0x00010000
        FILE_DELETE_ON_CLOSE = 0x00001000

        return (
            (desired & DELETE_ACCESS) != 0
            and (options & FILE_DELETE_ON_CLOSE) != 0
        )

    def classify_delete_target(self, pkt):
        options = pkt.get("smb2_create_options_raw") or 0

        try:
            options = int(options)
        except Exception:
            return "unknown"

        FILE_DIRECTORY_FILE = 0x00000001
        FILE_NON_DIRECTORY_FILE = 0x00000040

        if options & FILE_DIRECTORY_FILE:
            return "directory"

        if options & FILE_NON_DIRECTORY_FILE:
            return "file"

        return "unknown"
    
    
    def detect_delete_on_close(self, packets, status_lookup):
        events = []

        # map FileId -> CREATE delete-on-close request
        pending_delete_handles = {}

        for pkt in sorted(
            packets,
            key=lambda p: (
                float(p.get("timestamp") or 0),
                p.get("frame_number") or 0,
            )
        ):
            cmd = pkt.get("smb2_command_name")
            is_response = pkt.get("smb2_is_response")

            # 1. Capture CREATE with FILE_DELETE_ON_CLOSE.
            if self.is_delete_on_close_create(pkt):
                status = status_lookup.get(self._request_response_key(pkt))

                # If a matched response failed, ignore this pending delete.
                if status is not None and not self._status_success(status):
                    continue

                # FileId may be stored in mapped_file_id or smb2_file_id.
                fid = (
                    pkt.get("smb2_file_id")
                    or pkt.get("mapped_file_id")
                )

                # If the request has no FileId, fall back to path/session fields.
                key = fid or (
                    pkt.get("smb2_session_id"),
                    pkt.get("smb2_tree_id"),
                    pkt.get("smb2_filename"),
                )

                pending_delete_handles[key] = pkt
                continue

            # 2. Confirm deletion when CLOSE arrives for the same handle.
            if cmd == "CLOSE" and is_response is False:
                fid = (
                    pkt.get("smb2_file_id")
                    or pkt.get("mapped_file_id")
                )

                key_candidates = [fid]

                # Fallback when no file id is available.
                key_candidates.append((
                    pkt.get("smb2_session_id"),
                    pkt.get("smb2_tree_id"),
                    pkt.get("mapped_filename") or pkt.get("smb2_filename"),
                ))

                create_pkt = None
                matched_key = None

                for key in key_candidates:
                    if key in pending_delete_handles:
                        create_pkt = pending_delete_handles[key]
                        matched_key = key
                        break

                if not create_pkt:
                    continue

                close_status = status_lookup.get(self._request_response_key(pkt))

                if close_status is not None and not self._status_success(close_status):
                    continue

                target_type = self.classify_delete_target(create_pkt)
                path = create_pkt.get("smb2_filename") or create_pkt.get("mapped_filename")

                events.append({
                    "timestamp": self.safe_float(create_pkt.get("timestamp")),
                    "src_ip": create_pkt.get("src_ip"),
                    "dst_ip": create_pkt.get("dst_ip"),
                    "src_port": create_pkt.get("src_port"),
                    "dst_port": create_pkt.get("dst_port"),
                    "session_id": create_pkt.get("smb2_session_id"),
                    "tree_id": create_pkt.get("smb2_tree_id"),

                    "rule_id": "delete_on_close",
                    "action": f"deletion of {target_type} by delete-on-close",
                    "description": "CREATE with FILE_DELETE_ON_CLOSE followed by CLOSE on the same handle",

                    "path": path,
                    "file_id": fid,
                    "frames": [
                        create_pkt.get("frame_number"),
                        pkt.get("frame_number"),
                    ],
                    "commands": [
                        "CREATE",
                        "CLOSE",
                    ],
                    "success": True,
                    "statuses": [
                        status_lookup.get(self._request_response_key(create_pkt)),
                        close_status,
                    ],
                })

                if matched_key in pending_delete_handles:
                    del pending_delete_handles[matched_key]

        return events
