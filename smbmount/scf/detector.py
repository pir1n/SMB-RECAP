from smbmount.scf.fingerprint import fingerprint_sequence


class SCFDetector:

    def __init__(self, rules):

        self.rules = rules

    def detect(self, packets):

        events = []

        #
        # chỉ REQUEST packets
        #
        requests = [
            p for p in packets
            if p.get("smb2_is_response") is False
        ]

        #
        # sliding window
        #
        for i in range(len(requests)):

            for size in range(1, 5):

                seq = requests[i:i+size]

                if len(seq) < size:
                    continue

                fp = fingerprint_sequence(seq)

                for rule in self.rules:

                    if fp == rule["hash"]:

                        events.append({
                            "timestamp": seq[0].get("timestamp"),
                            "src_ip": seq[0].get("src_ip"),
                            "action": rule["action"],
                            "path": self.extract_path(seq),
                        })

        return events

    def extract_path(self, seq):

        for pkt in seq:

            if pkt.get("smb2_filename"):
                return pkt["smb2_filename"]

        return None