# SCF

Phát hiện hành động người dùng từ SMB traffic. Folder chứa detector, rules
runtime, fingerprint, tracker theo session/handle/directory, timeline và renderer.

SCF dùng parser trong `smbmount/shared` nhưng không chứa code reconstruction hay
filesystem mount.
