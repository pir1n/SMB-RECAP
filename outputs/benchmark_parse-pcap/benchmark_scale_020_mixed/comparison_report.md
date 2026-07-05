# SMB Reconstruction Benchmark Report

## 1. Tool của tôi: smbmount

| Metric | Value |
|---|---:|
| `version_tp` | 51 |
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
| `tp` | 51 |
| `fp` | 0 |
| `fn` | 0 |
| `precision` | 1.0000 |
| `recall` | 1.0000 |
| `f1` | 1.0000 |

### Content-only score `(md5, size)`

| Metric | Value |
|---|---:|
| `tp` | 51 |
| `fp` | 0 |
| `fn` | 0 |
| `precision` | 1.0000 |
| `recall` | 1.0000 |
| `f1` | 1.0000 |

### Mutation content score

| Metric | Value |
|---|---:|
| `tp` | 51 |
| `fp` | 0 |
| `fn` | 0 |
| `precision` | 1.0000 |
| `recall` | 1.0000 |
| `f1` | 1.0000 |

### Observed/read baseline score

Not applicable: This scenario has no observed/read baseline versions.


## 2. Tool gốc: pcapFS

| Metric | Value |
|---|---:|
| `version_tp` | 43 |
| `version_fp` | 9 |
| `version_fn` | 8 |
| `version_precision` | 0.8269 |
| `version_recall` | 0.8431 |
| `version_f1` | 0.8350 |
| `content_hash_accuracy` | 0.8431 |
| `size_accuracy` | 0.8431 |
| `version_count_error` | 1 |
| `index_content_hash_accuracy` | 0.9318 |

### Strict path content score `(path, md5, size)`

| Metric | Value |
|---|---:|
| `tp` | 43 |
| `fp` | 9 |
| `fn` | 8 |
| `precision` | 0.8269 |
| `recall` | 0.8431 |
| `f1` | 0.8350 |

### Content-only score `(md5, size)`

| Metric | Value |
|---|---:|
| `tp` | 46 |
| `fp` | 6 |
| `fn` | 5 |
| `precision` | 0.8846 |
| `recall` | 0.9020 |
| `f1` | 0.8932 |

### Mutation content score

Not applicable: pcapFS does not expose semantic operation labels, so mutation_content is not applicable.

### Observed/read baseline score

Not applicable: This scenario has no observed/read baseline versions.


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
    "path": "bench_scale_020_mixed\\dir_00\\sub_00\\file_0000_final.bin",
    "md5": "1db2a6d1a594672b46a6a6db99e5ccde",
    "size": 524800
  },
  {
    "path": "bench_scale_020_mixed\\dir_00\\sub_00\\file_0000_final.bin",
    "md5": "7ba28798b485035f812c6197dfdf0fce",
    "size": 524288
  },
  {
    "path": "bench_scale_020_mixed\\dir_00\\sub_00\\file_0000_final.bin",
    "md5": "a75d36bcd001cd89cb1112100b59e909",
    "size": 524800
  },
  {
    "path": "bench_scale_020_mixed\\dir_00\\sub_00\\file_0000_final.bin",
    "md5": "b8a5679bfbe76b5248cb3ed963575280",
    "size": 262400
  },
  {
    "path": "bench_scale_020_mixed\\dir_00\\sub_01\\file_0010.bin",
    "md5": "efd3396f7555e9adcd5ac399b4bc34b0",
    "size": 1929
  },
  {
    "path": "bench_scale_020_mixed\\dir_04\\sub_01\\file_0014_final.bin",
    "md5": "2ac3373311d5463cb40df8967a70fd5e",
    "size": 2856
  },
  {
    "path": "bench_scale_020_mixed\\dir_05\\sub_00\\file_0005.bin",
    "md5": "ca480ef6a53b954685269128fee5539f",
    "size": 986
  },
  {
    "path": "bench_scale_020_mixed\\dir_07\\sub_00\\file_0007_final.bin",
    "md5": "20073d4d8f386479d8b32ec556eb2bd8",
    "size": 2655
  }
]

### pcapFS extra versions

[
  {
    "path": "bench_scale_020_mixed\\dir_00\\sub_00\\file_0000.bin",
    "md5": "232ab3062063cce5e23eefe2aa1618cb",
    "size": 65536
  },
  {
    "path": "bench_scale_020_mixed\\dir_00\\sub_00\\file_0000.bin",
    "md5": "7ba28798b485035f812c6197dfdf0fce",
    "size": 524288
  },
  {
    "path": "bench_scale_020_mixed\\dir_00\\sub_00\\file_0000.bin",
    "md5": "b3d4cfbe25ca02a747b08fe53a65343f",
    "size": 262144
  },
  {
    "path": "bench_scale_020_mixed\\dir_00\\sub_00\\file_0000.bin",
    "md5": "d951ec495ca9c53cb2176592e361c48a",
    "size": 4096
  },
  {
    "path": "bench_scale_020_mixed\\dir_00\\sub_00\\file_0000_final.bin",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "size": 0
  },
  {
    "path": "bench_scale_020_mixed\\dir_04\\sub_01\\file_0014.bin",
    "md5": "05aa50d77a6700e069a6ba63dcb1c6b4",
    "size": 3213
  },
  {
    "path": "bench_scale_020_mixed\\dir_04\\sub_01\\file_0014.bin",
    "md5": "2ac3373311d5463cb40df8967a70fd5e",
    "size": 2856
  },
  {
    "path": "bench_scale_020_mixed\\dir_07\\sub_00\\file_0007.bin",
    "md5": "20073d4d8f386479d8b32ec556eb2bd8",
    "size": 2655
  },
  {
    "path": "bench_scale_020_mixed\\dir_07\\sub_00\\file_0007.bin",
    "md5": "58f77b9650fbb340a2a207213255a368",
    "size": 2986
  }
]

### pcapFS index wrong hash versions

[
  {
    "path": "bench_scale_020_mixed\\dir_04\\sub_01\\file_0014_final.bin",
    "version": 0,
    "expected_md5": "2ac3373311d5463cb40df8967a70fd5e",
    "predicted_md5": "05aa50d77a6700e069a6ba63dcb1c6b4"
  },
  {
    "path": "bench_scale_020_mixed\\dir_07\\sub_00\\file_0007_final.bin",
    "version": 0,
    "expected_md5": "20073d4d8f386479d8b32ec556eb2bd8",
    "predicted_md5": "58f77b9650fbb340a2a207213255a368"
  },
  {
    "path": "bench_scale_020_mixed\\dir_00\\sub_00\\file_0000_final.bin",
    "version": 0,
    "expected_md5": "7ba28798b485035f812c6197dfdf0fce",
    "predicted_md5": "d41d8cd98f00b204e9800998ecf8427e"
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
    "missing",
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
      "count": 20
    },
    {
      "expected": "append",
      "predicted": "metadata_update",
      "count": 20
    },
    {
      "expected": "delete",
      "predicted": "append",
      "count": 1
    },
    {
      "expected": "delete",
      "predicted": "missing",
      "count": 1
    },
    {
      "expected": "mkdir",
      "predicted": "context_seen",
      "count": 34
    },
    {
      "expected": "none",
      "predicted": "append",
      "count": 32
    },
    {
      "expected": "none",
      "predicted": "delete",
      "count": 6
    },
    {
      "expected": "none",
      "predicted": "metadata_update",
      "count": 4
    },
    {
      "expected": "none",
      "predicted": "mkdir",
      "count": 31
    },
    {
      "expected": "none",
      "predicted": "overwrite",
      "count": 9
    },
    {
      "expected": "none",
      "predicted": "read",
      "count": 47
    },
    {
      "expected": "none",
      "predicted": "rename",
      "count": 3
    },
    {
      "expected": "none",
      "predicted": "truncate",
      "count": 4
    },
    {
      "expected": "overwrite",
      "predicted": "append",
      "count": 6
    },
    {
      "expected": "overwrite",
      "predicted": "metadata_update",
      "count": 1
    },
    {
      "expected": "rename",
      "predicted": "context_seen",
      "count": 3
    },
    {
      "expected": "rmdir",
      "predicted": "mkdir",
      "count": 3
    },
    {
      "expected": "truncate",
      "predicted": "append",
      "count": 2
    },
    {
      "expected": "truncate",
      "predicted": "metadata_update",
      "count": 1
    },
    {
      "expected": "truncate",
      "predicted": "read",
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
