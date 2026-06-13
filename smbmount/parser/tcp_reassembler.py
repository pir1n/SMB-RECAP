from scapy.layers.inet import IP, TCP
from scapy.all import Raw, SMB2_Header, SMB2_Read_Response, SMB2_Write_Request
from smbmount.parser.utils import safe_get, safe_int

def reassemble_tcp_streams(capture_raw):
    """
    Tự reassemble TCP streams từ raw packets.
    Chỉ xử lý port 445 (SMB).
    """
    streams = {}
    
    for p in capture_raw:
        if not (p.haslayer(IP) and p.haslayer(TCP)):
            continue
        if p[TCP].dport != 445 and p[TCP].sport != 445:
            continue
        
        tcp_payload = bytes(p[TCP].payload)
        if not tcp_payload:
            continue
        
        key = (p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport)
        if key not in streams:
            streams[key] = {}
        
        seq = p[TCP].seq
        streams[key][seq] = tcp_payload
    
    # Ghép theo seq order
    reassembled = {}
    for key, seq_data in streams.items():
        sorted_seqs = sorted(seq_data.keys())
        buf = b""
        expected_seq = sorted_seqs[0]
        
        for seq in sorted_seqs:
            data = seq_data[seq]
            if seq == expected_seq:
                buf += data
                expected_seq = seq + len(data)
            elif seq < expected_seq:
                overlap = expected_seq - seq
                if overlap < len(data):
                    buf += data[overlap:]
                    expected_seq = seq + len(data)
            else:
                buf += data
                expected_seq = seq + len(data)
        
        reassembled[key] = buf
    
    # Parse SMB2 từ reassembled streams
    tcp_responses = {}
    tcp_write_requests = {}
    
    for key, buf in reassembled.items():
        pos = 0
        while pos < len(buf):
            magic = buf.find(b'\xfeSMB', pos)
            if magic == -1:
                break
            
            try:
                # SMB2 header layout (64 bytes):
                # offset 12: Command (2 bytes)
                # offset 16: Flags (4 bytes)
                # offset 20: NextCommand (4 bytes)
                # offset 28: MID (8 bytes)
                if magic + 64 > len(buf):
                    pos = magic + 4
                    continue
                
                cmd = int.from_bytes(buf[magic+12:magic+14], "little")
                flags = int.from_bytes(buf[magic+16:magic+20], "little")
                next_cmd = int.from_bytes(buf[magic+20:magic+24], "little")
                mid = int.from_bytes(buf[magic+24:magic+32], "little")
                is_resp = bool(flags & 0x01)
                
                # Chỉ parse scapy khi cần thiết
                if (is_resp and cmd == 8) or (not is_resp and cmd == 9):
                    hdr = SMB2_Header(buf[magic:])
                    
                    if is_resp and cmd == 8 and hdr.haslayer(SMB2_Read_Response):
                        read_resp = hdr[SMB2_Read_Response]
                        expected_len = safe_int(safe_get(read_resp, "DataLen")) or 0
                        actual_data = b""
                        for name, val in (safe_get(read_resp, "Buffer") or []):
                            if name == "Data":
                                actual_data = val if isinstance(val, bytes) else bytes(val)
                                break
                        # if len(actual_data) < expected_len:
                            # print(f"[INCOMPLETE READ] MID={mid} expected={expected_len} got={len(actual_data)}")
                        if key not in tcp_responses:
                            tcp_responses[key] = {}
                        tcp_responses[key][mid] = hdr

                    elif not is_resp and cmd == 9 and hdr.haslayer(SMB2_Write_Request):
                        # print(f"[WRITE CMD9] MID={mid} has_write_req={hdr.haslayer(SMB2_Write_Request) if 'hdr' in dir() else 'not parsed'} buf_size={len(buf)}")
                        
                        write_req = hdr[SMB2_Write_Request]
                        expected_len = safe_int(safe_get(write_req, "DataLen")) or 0
                        actual_data = b""
                        for name, val in (safe_get(write_req, "Buffer") or []):
                            if name == "Data":
                                actual_data = val if isinstance(val, bytes) else bytes(val)
                                break
                            
                        # if expected_len > 1000:
                        #     print(f"[WRITE REASSEMBLE] MID={mid} expected={expected_len} got={len(actual_data)} buf_size={len(buf)}")
                        # if len(actual_data) < expected_len:
                        #     print(f"[INCOMPLETE WRITE] MID={mid} expected={expected_len} got={len(actual_data)}")
                            
                        # if len(actual_data) < expected_len:
                        #     print(f"[INCOMPLETE WRITE] MID={mid} expected={expected_len} got={len(actual_data)}")
                        
                        if key not in tcp_write_requests:
                            tcp_write_requests[key] = {}
                        tcp_write_requests[key][mid] = hdr
                
                # Advance
                if next_cmd > 0:
                    pos = magic + next_cmd
                else:
                    pos = magic + 4

            except Exception:
                pos = magic + 4
    
    return tcp_responses, tcp_write_requests