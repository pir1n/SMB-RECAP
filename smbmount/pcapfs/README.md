# PCAP filesystem

Chức năng dựng lại filesystem và các phiên bản file từ PCAP:

- `reconstruct/`: nội dung, metadata, timestamp, hierarchy và versioning.
- `output/`: JSON/snapshot export và FUSE mount.
- `benchmark/`: normalize và score output file-version của SMBmount/pcapFS.

Tên `pcapfs` ở đây chỉ nhóm chức năng trong SMBmount; source pcapFS chính thức
vẫn là project độc lập bên ngoài và không được sao chép vào đây.
