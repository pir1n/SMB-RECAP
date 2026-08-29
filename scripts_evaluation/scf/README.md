# SCF scripts

Chạy experiment, FKIE comparison, ablation/robustness, audit ground truth và
strict/relaxed timeline scoring. Script sinh workload được tách sang
`../data_generators/scf`.

Relaxed scoring có thể loại các lệnh listing được phục vụ từ SMB client cache,
nhưng chỉ khi raw SCF dump không chứa `QUERY_DIRECTORY` trong command window:

```powershell
.\.venv\Scripts\python.exe scripts_evaluation\scf\score_timeline.py `
  --ground-truth ground_truth.jsonl `
  --timeline RUN_ID=timeline.json `
  --out-dir metrics `
  --relaxed-ignore-cached-listings `
  --scf-dump RUN_ID=scf_dump.json `
  --observability-session-tree "<SESSION_ID>:<TREE_ID>"
```

Strict metrics luôn giữ nguyên toàn bộ ground truth. Relaxed output ghi các hàng
bị loại tại `relaxed/not_observable_cached_listings.json` để audit.
