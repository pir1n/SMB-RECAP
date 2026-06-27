# SMB Reconstruction Benchmark Report

## 1. Tool của tôi: smbmount

| Metric | Value |
|---|---:|
| `version_tp` | 9 |
| `version_fp` | 0 |
| `version_fn` | 0 |
| `version_precision` | 1.0000 |
| `version_recall` | 1.0000 |
| `version_f1` | 1.0000 |
| `content_hash_accuracy` | 1.0000 |
| `size_accuracy` | 1.0000 |
| `version_count_error` | 0 |
| `index_content_hash_accuracy` | 1.0000 |

### Strict path content score `(path, md5, size)`

| Metric | Value |
|---|---:|
| `tp` | 9 |
| `fp` | 0 |
| `fn` | 0 |
| `precision` | 1.0000 |
| `recall` | 1.0000 |
| `f1` | 1.0000 |

### Content-only score `(md5, size)`

| Metric | Value |
|---|---:|
| `tp` | 9 |
| `fp` | 0 |
| `fn` | 0 |
| `precision` | 1.0000 |
| `recall` | 1.0000 |
| `f1` | 1.0000 |

### Mutation content score

| Metric | Value |
|---|---:|
| `tp` | 9 |
| `fp` | 0 |
| `fn` | 0 |
| `precision` | 1.0000 |
| `recall` | 1.0000 |
| `f1` | 1.0000 |

### Observed/read baseline score

| Metric | Value |
|---|---:|
| `tp` | 0 |
| `fp` | 0 |
| `fn` | 0 |
| `precision` | 0.0000 |
| `recall` | 0.0000 |
| `f1` | 0.0000 |


## 2. Tool gốc: pcapFS

| Metric | Value |
|---|---:|
| `version_tp` | 4 |
| `version_fp` | 4 |
| `version_fn` | 5 |
| `version_precision` | 0.5000 |
| `version_recall` | 0.4444 |
| `version_f1` | 0.4706 |
| `content_hash_accuracy` | 0.4444 |
| `size_accuracy` | 0.4444 |
| `version_count_error` | -1 |
| `index_content_hash_accuracy` | 0.8000 |

### Strict path content score `(path, md5, size)`

| Metric | Value |
|---|---:|
| `tp` | 4 |
| `fp` | 4 |
| `fn` | 5 |
| `precision` | 0.5000 |
| `recall` | 0.4444 |
| `f1` | 0.4706 |

### Content-only score `(md5, size)`

| Metric | Value |
|---|---:|
| `tp` | 7 |
| `fp` | 1 |
| `fn` | 2 |
| `precision` | 0.8750 |
| `recall` | 0.7778 |
| `f1` | 0.8235 |

### Mutation content score

Not applicable: pcapFS does not expose semantic operation labels, so mutation_content is not applicable.

### Observed/read baseline score

| Metric | Value |
|---|---:|
| `tp` | 0 |
| `fp` | 0 |
| `fn` | 0 |
| `precision` | 0.0000 |
| `recall` | 0.0000 |
| `f1` | 0.0000 |


## 3. Cách đọc metric

- `strict_path_content`: chấm theo `(path, md5, size)`. Metric này phạt lỗi rename/path.
- `content_only`: chấm theo `(md5, size)`. Metric này đo khả năng recover content, bỏ qua khác biệt path.
- `mutation_content`: chấm các version do WRITE/TRUNCATE tạo ra.
- `observed_content`: chấm các baseline version do READ hợp lệ tạo ra.
- `index_*`: metric debug theo `(path, version_number)`, không nên dùng làm kết luận chính.
- `event_confusion`: chỉ có ý nghĩa với smbmount vì pcapFS không xuất semantic SMB event timeline.

## 4. Missing / Extra / Wrong Hash

### smbmount missing versions

[]

### smbmount extra versions

[]

### smbmount index wrong hash versions

[]

### pcapFS missing versions

[
  {
    "path": "bench_multi_version_001\\bin\\large.bin",
    "md5": "2f303f70ae2a9312336615fd61868549",
    "size": 1500000
  },
  {
    "path": "bench_multi_version_001\\docs\\notes.txt",
    "md5": "781e5e245d69b566979b86e28d23f2c7",
    "size": 10
  },
  {
    "path": "bench_multi_version_001\\docs\\report_final.txt",
    "md5": "75bafddaa9e8e5c67e20b0f3f91512c1",
    "size": 11
  },
  {
    "path": "bench_multi_version_001\\docs\\report_final.txt",
    "md5": "852e77b490fb4e8653fbc11f4c6f89c2",
    "size": 11
  },
  {
    "path": "bench_multi_version_001\\docs\\report_final.txt",
    "md5": "9f9f90dbe3e5ee1218c86b8839db1995",
    "size": 6
  }
]

### pcapFS extra versions

[
  {
    "path": "bench_multi_version_001\\bin\\large.bin",
    "md5": "2a198110996c4149a216639e1d5fb1d1",
    "size": 262144
  },
  {
    "path": "bench_multi_version_001\\docs\\report.txt",
    "md5": "75bafddaa9e8e5c67e20b0f3f91512c1",
    "size": 11
  },
  {
    "path": "bench_multi_version_001\\docs\\report.txt",
    "md5": "852e77b490fb4e8653fbc11f4c6f89c2",
    "size": 11
  },
  {
    "path": "bench_multi_version_001\\docs\\report.txt",
    "md5": "9f9f90dbe3e5ee1218c86b8839db1995",
    "size": 6
  }
]

### pcapFS index wrong hash versions

[
  {
    "path": "bench_multi_version_001\\bin\\large.bin",
    "version": 1,
    "expected_md5": "2f303f70ae2a9312336615fd61868549",
    "predicted_md5": "2a198110996c4149a216639e1d5fb1d1"
  }
]

## 5. Event Confusion 

### smbmount

{
  "labels": [
    "append",
    "context_seen",
    "delete",
    "metadata_update",
    "mkdir",
    "none",
    "overwrite",
    "read",
    "rename",
    "rmdir",
    "truncate"
  ],
  "matrix": [
    {
      "expected": "append",
      "predicted": "context_seen",
      "count": 5
    },
    {
      "expected": "append",
      "predicted": "metadata_update",
      "count": 1
    },
    {
      "expected": "delete",
      "predicted": "metadata_update",
      "count": 1
    },
    {
      "expected": "mkdir",
      "predicted": "context_seen",
      "count": 5
    },
    {
      "expected": "none",
      "predicted": "append",
      "count": 7
    },
    {
      "expected": "none",
      "predicted": "context_seen",
      "count": 1
    },
    {
      "expected": "none",
      "predicted": "delete",
      "count": 2
    },
    {
      "expected": "none",
      "predicted": "metadata_update",
      "count": 5
    },
    {
      "expected": "none",
      "predicted": "mkdir",
      "count": 5
    },
    {
      "expected": "none",
      "predicted": "overwrite",
      "count": 2
    },
    {
      "expected": "none",
      "predicted": "read",
      "count": 10
    },
    {
      "expected": "none",
      "predicted": "rename",
      "count": 1
    },
    {
      "expected": "none",
      "predicted": "truncate",
      "count": 1
    },
    {
      "expected": "overwrite",
      "predicted": "append",
      "count": 1
    },
    {
      "expected": "overwrite",
      "predicted": "metadata_update",
      "count": 1
    },
    {
      "expected": "rename",
      "predicted": "context_seen",
      "count": 1
    },
    {
      "expected": "rmdir",
      "predicted": "mkdir",
      "count": 1
    },
    {
      "expected": "truncate",
      "predicted": "metadata_update",
      "count": 1
    }
  ]
}

### pcapFS

{
  "note": "pcapFS exposes reconstructed filesystem content, not semantic SMB event timeline. Event confusion is not applicable.",
  "labels": [],
  "matrix": []
}
