## Project Structure

Please make environment for python before running

```
$ python -m venv .venv
```

To run project:
```python
python -m smbmount parse-pcap .\data\pcaps\Sample2.pcapng .\outputs\metadatatree.json                                                                    
```

Use scf-dump to dump scf hash
```
python -m smbmount scf-dump .\data\pcaps\test_versioning_modfied_on_file.pcapng .\outputs\scf_dump_2.json                                       
```
Use scf to run with to and generate timeline command
```
python -m smbmount scf .\data\pcaps\testSCFsample.pcapng .\rules\scf_rules.json .\outputs\scf_timeline.json                                    
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