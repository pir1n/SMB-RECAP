# SMB Reconstruction Benchmark Report

## 1. Tool của tôi: smbmount

| Metric | Value |
|---|---:|
| `version_tp` | 13 |
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
| `tp` | 13 |
| `fp` | 0 |
| `fn` | 0 |
| `precision` | 1.0000 |
| `recall` | 1.0000 |
| `f1` | 1.0000 |

### Content-only score `(md5, size)`

| Metric | Value |
|---|---:|
| `tp` | 13 |
| `fp` | 0 |
| `fn` | 0 |
| `precision` | 1.0000 |
| `recall` | 1.0000 |
| `f1` | 1.0000 |

### Mutation content score

| Metric | Value |
|---|---:|
| `tp` | 13 |
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
| `version_tp` | 4 |
| `version_fp` | 9 |
| `version_fn` | 9 |
| `version_precision` | 0.3077 |
| `version_recall` | 0.3077 |
| `version_f1` | 0.3077 |
| `content_hash_accuracy` | 0.3077 |
| `size_accuracy` | 0.3077 |
| `version_count_error` | 0 |
| `index_content_hash_accuracy` | 0.4444 |

### Strict path content score `(path, md5, size)`

| Metric | Value |
|---|---:|
| `tp` | 4 |
| `fp` | 9 |
| `fn` | 9 |
| `precision` | 0.3077 |
| `recall` | 0.3077 |
| `f1` | 0.3077 |

### Content-only score `(md5, size)`

| Metric | Value |
|---|---:|
| `tp` | 5 |
| `fp` | 8 |
| `fn` | 8 |
| `precision` | 0.3846 |
| `recall` | 0.3846 |
| `f1` | 0.3846 |

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
    "path": "bench_scale_005_large_chunks\\dir_00\\sub_00\\file_0000_final.bin",
    "md5": "4d58aa759c644e7873c78adb501bc957",
    "size": 4194816
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_00\\sub_00\\file_0000_final.bin",
    "md5": "6bbdba893727c511a7203ac73f2e3989",
    "size": 2097408
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_00\\sub_00\\file_0000_final.bin",
    "md5": "b3c2f878f041915f5453d5be69899d78",
    "size": 4194816
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_00\\sub_00\\file_0000_final.bin",
    "md5": "cc833fbbc37bd4481a463c1efe215b1a",
    "size": 4194304
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_01\\sub_00\\file_0001.bin",
    "md5": "628bb6502a225447b871b6fe449d8293",
    "size": 4194816
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_02\\sub_00\\file_0002.bin",
    "md5": "8c0e65312bd15517acb70e98b5cc90f8",
    "size": 4194816
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_03\\sub_00\\file_0003.bin",
    "md5": "c223558c02e0c11834ae9f16b26ab203",
    "size": 4194816
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_03\\sub_00\\file_0003.bin",
    "md5": "e850dbdadc0909a1d20a427db0ad1e37",
    "size": 4194816
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_04\\sub_00\\file_0004.bin",
    "md5": "d3f04c0ca2928069981df226215e6871",
    "size": 4194816
  }
]

### pcapFS extra versions

[
  {
    "path": "bench_scale_005_large_chunks\\dir_00\\sub_00\\file_0000.bin",
    "md5": "5c231f1b8953507b49f678f5656b976b",
    "size": 4096
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_00\\sub_00\\file_0000.bin",
    "md5": "cc833fbbc37bd4481a463c1efe215b1a",
    "size": 4194304
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_00\\sub_00\\file_0000.bin",
    "md5": "e6450ddec45af4cfa0833164120b92cb",
    "size": 65536
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_00\\sub_00\\file_0000.bin",
    "md5": "e7365633e4ae9ef44ab981fae0bfc863",
    "size": 262144
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_00\\sub_00\\file_0000_final.bin",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "size": 0
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_01\\sub_00\\file_0001.bin",
    "md5": "d5bc66fd735e14ee2e6b18916bac2025",
    "size": 262144
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_02\\sub_00\\file_0002.bin",
    "md5": "5f016de1897ad236f6cb2f058be5c419",
    "size": 262144
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_03\\sub_00\\file_0003.bin",
    "md5": "7a080730a4ddc08f83342fa83065d6e1",
    "size": 262144
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_04\\sub_00\\file_0004.bin",
    "md5": "d100461e36b05f6f77b7fd0b8aeaa747",
    "size": 262144
  }
]

### pcapFS index wrong hash versions

[
  {
    "path": "bench_scale_005_large_chunks\\dir_03\\sub_00\\file_0003.bin",
    "version": 1,
    "expected_md5": "e850dbdadc0909a1d20a427db0ad1e37",
    "predicted_md5": "7a080730a4ddc08f83342fa83065d6e1"
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_01\\sub_00\\file_0001.bin",
    "version": 1,
    "expected_md5": "628bb6502a225447b871b6fe449d8293",
    "predicted_md5": "d5bc66fd735e14ee2e6b18916bac2025"
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_04\\sub_00\\file_0004.bin",
    "version": 1,
    "expected_md5": "d3f04c0ca2928069981df226215e6871",
    "predicted_md5": "d100461e36b05f6f77b7fd0b8aeaa747"
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_02\\sub_00\\file_0002.bin",
    "version": 1,
    "expected_md5": "8c0e65312bd15517acb70e98b5cc90f8",
    "predicted_md5": "5f016de1897ad236f6cb2f058be5c419"
  },
  {
    "path": "bench_scale_005_large_chunks\\dir_00\\sub_00\\file_0000_final.bin",
    "version": 0,
    "expected_md5": "cc833fbbc37bd4481a463c1efe215b1a",
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
      "count": 5
    },
    {
      "expected": "append",
      "predicted": "metadata_update",
      "count": 5
    },
    {
      "expected": "delete",
      "predicted": "missing",
      "count": 1
    },
    {
      "expected": "mkdir",
      "predicted": "context_seen",
      "count": 19
    },
    {
      "expected": "none",
      "predicted": "append",
      "count": 35
    },
    {
      "expected": "none",
      "predicted": "delete",
      "count": 5
    },
    {
      "expected": "none",
      "predicted": "metadata_update",
      "count": 23
    },
    {
      "expected": "none",
      "predicted": "mkdir",
      "count": 16
    },
    {
      "expected": "none",
      "predicted": "overwrite",
      "count": 4
    },
    {
      "expected": "none",
      "predicted": "read",
      "count": 40
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
      "predicted": "metadata_update",
      "count": 2
    },
    {
      "expected": "rename",
      "predicted": "context_seen",
      "count": 1
    },
    {
      "expected": "rmdir",
      "predicted": "mkdir",
      "count": 3
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
