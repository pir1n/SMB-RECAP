from collections import defaultdict

from smbmount.scf.fingerprint import (
    fingerprint_packet,
    fingerprint_sequence,
)


class SCFDetector:

    def __init__(self, rules):
        self.rules = rules

    def detect(self, packets):
        events = []

        status_lookup = self._build_response_status_lookup(packets)
        groups = self._group_requests(packets)

        # Ưu tiên rule dài trước để tránh rule ngắn ăn mất rule dài.
        sorted_rules = sorted(
            self.rules,
            key=lambda r: len(r.get("pattern", [])),
            reverse=True,
        )

        for group_key, requests in groups.items():
            requests = sorted(
                requests,
                key=lambda p: (
                    p.get("timestamp") or 0,
                    p.get("frame_number") or 0,
                )
            )

            packet_hashes = [fingerprint_packet(pkt) for pkt in requests]

            for i in range(len(requests)):
                for rule in sorted_rules:
                    match = self._match_rule(
                        rule=rule,
                        requests=requests,
                        packet_hashes=packet_hashes,
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
                        "file_id": self.extract_file_id(seq),

                        "frames": [p.get("frame_number") for p in seq],
                        "commands": [p.get("smb2_command_name") for p in seq],
                        "packet_scfs": match["packet_scfs"],
                        "sequence_scf": fingerprint_sequence(seq),

                        "statuses": statuses,
                        "success": self._sequence_success(statuses),
                    })

                    # Đã match rule dài nhất tại vị trí này thì không cần match rule ngắn hơn.
                    break

        return events

    def _match_rule(self, rule, requests, packet_hashes, start, status_lookup):
        # Rule mới: match list SCF từng packet
        if "pattern" in rule:
            pattern = rule["pattern"]
            size = len(pattern)
            end = start + size

            if end > len(requests):
                return None

            if packet_hashes[start:end] != pattern:
                return None

            seq = requests[start:end]
            statuses = self._statuses_for_sequence(seq, status_lookup)

            if rule.get("require_success") and not self._sequence_success(statuses):
                return None

            return {
                "seq": seq,
                "statuses": statuses,
                "packet_scfs": packet_hashes[start:end],
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

                if rule.get("require_success") and not self._sequence_success(statuses):
                    return None

                return {
                    "seq": seq,
                    "statuses": statuses,
                    "packet_scfs": packet_hashes[start:start + size],
                }

        return None

    def _group_requests(self, packets):
        groups = defaultdict(list)

        for pkt in packets:
            if pkt.get("smb2_is_response") is not False:
                continue

            key = self._request_group_key(pkt)
            groups[key].append(pkt)

        return groups

    def _request_group_key(self, pkt):
        return (
            pkt.get("src_ip"),
            pkt.get("dst_ip"),
            pkt.get("src_port"),
            pkt.get("dst_port"),
            pkt.get("smb2_session_id"),
            pkt.get("smb2_tree_id"),
        )

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
        # Response đi ngược chiều request, nên đảo src/dst và port.
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

        # Nếu không có response nào match được thì unknown.
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

    def extract_file_id(self, seq):
        for pkt in seq:
            if pkt.get("smb2_file_id"):
                fid = pkt["smb2_file_id"]
                return fid.hex() if isinstance(fid, bytes) else fid

            if pkt.get("mapped_file_id"):
                fid = pkt["mapped_file_id"]
                return fid.hex() if isinstance(fid, bytes) else fid

        return None