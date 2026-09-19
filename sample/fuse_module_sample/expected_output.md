# Expected Output - fuse_module_sample

Sample này dùng:

```text
PCAP: sample/fuse_module_sample/pcaps/scale_0050_mixed.pcapng
Ground truth: sample/fuse_module_sample/ground_truth/scale_0050_mixed.json
Scenario dir: bench_scale_0050_mixed
Files: 50
Expected content versions: 90
Events: 151
```

## parse-pcap

Lệnh chạy:

```bash
python -m smb_recap parse-pcap \
  sample/fuse_module_sample/pcaps/scale_0050_mixed.pcapng \
  outputs/fuse_module_sample/manual/scale_0050_mixed.json \
  --timestamp-mode network
```

Expected console output:

```text
Reading PCAP: sample/fuse_module_sample/pcaps/scale_0050_mixed.pcapng
Output JSON: outputs/fuse_module_sample/manual/scale_0050_mixed.json
Timestamp mode: network
Reader: streaming
Streaming PCAP file...
[stream] complete: packets=14119 bytes=2514659 smb_records=14129 active_flows=2 rss_mb=...
Done.
```

`rss_mb` phụ thuộc máy chạy nên chỉ cần đối chiếu các trường cố định:

```text
packets=14119
bytes=2514659
smb_records=14129
active_flows=2
```

## Benchmark Metrics

Khi chấm bằng `python -m smb_recap.benchmark_parsepcap.cli`, expected console output:

```text
Benchmark complete: outputs/fuse_module_sample/manual/benchmark
Scenario dir: bench_scale_0050_mixed
```

Expected metrics:

| Tool | strict_path_content TP/FP/FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| SMB-RECAP parse-pcap | 90/0/0 | 1.0000 | 1.0000 | 1.0000 |
| pcapFS | 80/13/10 | 0.8602 | 0.8889 | 0.8743 |

Expected `ours_metrics.json` values:

```json
{
  "version_tp": 90,
  "version_fp": 0,
  "version_fn": 0,
  "version_precision": 1.0,
  "version_recall": 1.0,
  "version_f1": 1.0,
  "version_count_error": 0
}
```

Expected `pcapfs_metrics.json` values:

```json
{
  "version_tp": 80,
  "version_fp": 13,
  "version_fn": 10,
  "version_precision": 0.8602150537634409,
  "version_recall": 0.8888888888888888,
  "version_f1": 0.8743169398907102,
  "version_count_error": 3
}
```

## measure_runtime.sh

Lệnh chạy mặc định:

```bash
sample/fuse_module_sample/measure_runtime.sh --repeats 5
```

Expected output shape:

```text
[CASE] scale_0050_mixed
  Files: 50
  PCAP: .../sample/fuse_module_sample/pcaps/scale_0050_mixed.pcapng
  Ground truth: .../sample/fuse_module_sample/ground_truth/scale_0050_mixed.json
  Scenario dir: bench_scale_0050_mixed
  Repeats: 5
    [SMB-RECAP] parse run 1
    [pcapFS] mount + normalize/hash + score run 1
    ...

[OK] CSV: outputs/fuse_module_sample/runtime_metrics.csv

Repeated benchmark summary
...
```

Expected CSV columns:

```text
tool,case,files,run,runtime_s,precision,recall,f1,status,extra
```

Expected successful rows contain:

```text
smbmount,scale_0050_mixed,50,<run>,<runtime>,1.0,1.0,1.0,ok,<json_path>
pcapFS,scale_0050_mixed,50,<run>,<runtime>,0.8602150537634409,0.8888888888888888,0.8743169398907102,ok,<mountpoint>
```

The CSV retains the legacy machine identifier `smbmount` so archived benchmark outputs remain comparable; manuscript tables use the public name SMB-RECAP.

`runtime_s`, absolute paths and RSS memory vary by machine.
