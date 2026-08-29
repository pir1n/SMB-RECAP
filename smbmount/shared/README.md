# Shared source

Code được cả SCF và PCAP filesystem sử dụng:

- `parser/`: decode PCAP/TCP/SMB2 và request-response correlation.
- `core/`: session và file-table primitives.
- `evaluation.py`: schema/path/JSON helpers dùng bởi generator và scorer.

Không đặt rules SCF hoặc implementation FUSE riêng trong folder này.
