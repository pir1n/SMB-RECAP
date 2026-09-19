from typing import Dict, List


class SMBMessage:
    def __init__(self, record: dict):
        self.raw = record
        self.msg_id = record.get("smb2_message_id")
        self.is_response = record.get("smb2_is_response")
        self.command = record.get("smb2_command_name")


class SMBSession:
    def __init__(self):
        self.requests: Dict[str, SMBMessage] = {}
        self.responses: Dict[str, SMBMessage] = {}
        self.pairs: List[tuple] = []

    def add(self, record: dict):
        msg = SMBMessage(record)

        if msg.msg_id is None:
            return

        if not msg.is_response:
            self.requests[msg.msg_id] = msg
        else:
            self.responses[msg.msg_id] = msg

            if msg.msg_id in self.requests:
                req = self.requests[msg.msg_id]
                self.pairs.append((req.raw, record))

    def build(self, packets: List[dict]):
        for pkt in packets:
            self.add(pkt)

        return self.pairs