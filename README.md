## Project Structure

Please make environment for python before running

```
$ python -m venv .venv
```

To run project:
```python
python -m smbmount parse-pcap .\data\pcaps\Sample2.pcapng .\outputs\metadatatree.json                                                                    
```

Use scf-dump to dump SCF v2 hash, normalized string, and semantic features:
```
python -m smbmount scf-dump .\data\pcaps\test_versioning_modfied_on_file.pcapng .\outputs\scf_dump_2.json                                       
```
Use SCF with built-in semantic rules:
```
python -m smbmount scf .\data\pcaps\testSCFsample.pcapng .\outputs\scf_timeline.json
```

Use SCF with a custom rule file:
```
python -m smbmount scf .\data\pcaps\testSCFsample.pcapng .\rules\scf_rules.json .\outputs\scf_timeline.json                                    
```

Use both built-in rules and a custom rule file:
```
python -m smbmount scf --with-builtin-rules .\data\pcaps\testSCFsample.pcapng .\rules\scf_rules.json .\outputs\scf_timeline.json
```

SCF v2 normalizes SMB commands into semantic features and excludes volatile values
such as path, file id, offsets, lengths, and data bytes. Rule pattern entries may
match raw SCF hashes, normalized strings, command names, or feature objects.

```
SMBmount
├── README.md
├── data
│   └── pcaps
│       ├── Sample2.pcapng
│       └── sample.pcapng
├── debug.json
├── note.txt
├── outputs
│   ├── raw_packets.json
│   ├── raw_packets2.json
│   └── sample.json
├── requirements.txt
└── smbmount
    ├── __init__.py
    ├── __main__.py
    ├── cli.py
    ├── core
    │   ├── file_table.py
    │   └── session.py
    ├── output
    │   └── fs_export.py
    ├── parser
    │   ├── __init__.py
    │   └── pcap_reader.py
    └── reconstruct
        ├── content.py
        ├── hierarchy.py
        ├── metadata.py
        └── versioning.py
```

to matched right version fix view extension of file to copy it to main file to run.
