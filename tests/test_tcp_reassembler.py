import unittest

from smbmount.parser.tcp_reassembler import iter_smb2_messages_from_tcp_payload


class IterSmb2MessagesTests(unittest.TestCase):
    def test_zero_length_false_nbss_header_before_magic_terminates(self):
        # Regression for cmd_operation_scale_100_tshark.pcapng frame 34140:
        # a mid-stream TCP fragment has four zero bytes immediately before an
        # SMB2 magic value.  The old parser repeatedly selected the same magic.
        smb2_header = bytearray(64)
        smb2_header[:4] = b"\xfeSMB"
        smb2_header[12:14] = (14).to_bytes(2, "little")
        payload = b"fragment-data" + b"\x00\x00\x00\x00" + bytes(smb2_header)

        messages = list(iter_smb2_messages_from_tcp_payload(payload))

        self.assertEqual(messages, [bytes(smb2_header)])

    def test_valid_nbss_frame_still_parses(self):
        smb2_header = bytearray(64)
        smb2_header[:4] = b"\xfeSMB"
        nbss = b"\x00" + len(smb2_header).to_bytes(3, "big")

        messages = list(iter_smb2_messages_from_tcp_payload(nbss + smb2_header))

        self.assertEqual(messages, [bytes(smb2_header)])


if __name__ == "__main__":
    unittest.main()
