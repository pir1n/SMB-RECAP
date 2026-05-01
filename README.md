## Project Structure

Please make environment for python before to run

```
$ python -m venv .venv
```

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