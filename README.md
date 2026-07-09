# SMBmount

SMBmount là toolkit đọc PCAP/PCAPNG chứa SMB2/SMB3 traffic, trích xuất metadata, nhận diện hành vi bằng Semantic Command Fingerprint (SCF), dựng timeline hoạt động và đánh giá kết quả với ground truth.

Phần SCF hiện tập trung vào các thao tác SMB phổ biến:

- create/remove directory
- create/remove file
- list directory
- upload/download file
- read/view file
- append/write/overwrite file
- rename/move file hoặc directory

Các rule JSON hiện nằm trong:

```text
rules/cmd_rules.json
rules/powershell_rules.json
rules/smbclient_rules.json
```

## Cài Đặt

Tạo và kích hoạt virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Kiểm tra CLI:

```powershell
.\.venv\Scripts\python.exe -m smbmount --help
```

## Tổng Quan SCF

SCF không so khớp trực tiếp raw packet cố định. Mỗi SMB request được chuẩn hóa thành semantic features như:

- SMB command: `CREATE`, `READ`, `WRITE`, `SET_INFO`, `QUERY_DIRECTORY`
- access intent: `read`, `write`, `delete`, `metadata`
- target type: `file`, `directory`, `unknown`
- create result: `created`, `opened`, `overwritten`
- file information class cho rename/delete/listing
- I/O length class

Những giá trị quá động như path, file id, offset, raw length và data bytes không được đưa vào fingerprint chính để rule có thể tổng quát hơn.

Một rule JSON thường có dạng:

```json
{
  "id": "cmd_copy_upload",
  "action": "upload file",
  "pattern": [
    {
      "command": "CREATE",
      "features": {
        "target_type": "file"
      },
      "contains": {
        "access_intents": ["write"]
      }
    },
    {
      "command": "WRITE",
      "features": {
        "length_class": "nonzero"
      }
    }
  ],
  "max_gap": 24,
  "require_success": true
}
```

## Dựng Timeline SCF

Chạy SCF với rule file:

```powershell
.\.venv\Scripts\python.exe -m smbmount scf `
  data\eval\pcaps\<RUN_ID>.pcapng `
  rules\cmd_rules.json `
  outputs\eval\timelines\<RUN_ID>_timeline.json
```

Mặc định lệnh `scf`:

- ghi timeline ra JSON
- không in bảng Rich để chạy nhanh hơn
- in progress mỗi 10% trong bước detect

Tắt progress nếu cần log sạch:

```powershell
.\.venv\Scripts\python.exe -m smbmount scf `
  data\eval\pcaps\<RUN_ID>.pcapng `
  rules\cmd_rules.json `
  outputs\eval\timelines\<RUN_ID>_timeline.json `
  --no-progress
```

In bảng timeline như logic cũ:

```powershell
.\.venv\Scripts\python.exe -m smbmount scf `
  data\eval\pcaps\<RUN_ID>.pcapng `
  rules\cmd_rules.json `
  outputs\eval\timelines\<RUN_ID>_timeline.json `
  --print-table
```

Kết hợp cả custom rules và built-in rules:

```powershell
.\.venv\Scripts\python.exe -m smbmount scf `
  data\eval\pcaps\<RUN_ID>.pcapng `
  rules\cmd_rules.json `
  outputs\eval\timelines\<RUN_ID>_timeline.json `
  --with-builtin-rules
```

## Dump SCF Features

Khi cần viết hoặc debug rule, dump normalized SCF:

```powershell
.\.venv\Scripts\python.exe -m smbmount scf-dump `
  data\eval\pcaps\<RUN_ID>.pcapng `
  outputs\eval\tshark\<RUN_ID>_scf_dump.json
```

File dump gồm frame number, timestamp, command, path, normalized SCF string và semantic features.

## Generate Workload Đánh Giá

Script chính:

```text
scripts/eval/generate_operation_scale.py
```

Tạo workload cho CMD:

```powershell
$RUN_ID = "cmd_operation_scale_100_tshark"

.\.venv\Scripts\python.exe scripts\eval\generate_operation_scale.py `
  --client cmd `
  --count-per-operation 100 `
  --run-id $RUN_ID `
  --out-dir data\eval\generated `
  --render `
  --drive Z
```

Tạo workload nhanh cho CMD:

```powershell
.\.venv\Scripts\python.exe scripts\eval\generate_operation_scale.py `
  --client cmd `
  --count-per-operation 100 `
  --run-id $RUN_ID `
  --out-dir data\eval\generated `
  --render `
  --drive Z `
  --fast-workload `
  --progress-every 100
```

Tạo workload nhanh cho PowerShell:

```powershell
$RUN_ID = "powershell_operation_scale_100_tshark"

.\.venv\Scripts\python.exe scripts\eval\generate_operation_scale.py `
  --client powershell `
  --count-per-operation 100 `
  --run-id $RUN_ID `
  --out-dir data\eval\generated `
  --render `
  --drive Z `
  --fast-workload `
  --progress-every 100
```

Tạo workload cho smbclient:

```bash
RUN_ID="smbclient_operation_scale_100_tshark"

python scripts/eval/generate_operation_scale.py \
  --client smbclient \
  --count-per-operation 100 \
  --run-id "$RUN_ID" \
  --out-dir data/eval/generated \
  --render \
  --server 192.168.106.131 \
  --share SMB_EVAL \
  --auth-file /tmp/smb_eval.auth \
  --local-dir /tmp/smbmount_scf_eval \
  --progress-every 100
```

Ghi chú:

- `--fast-workload` chỉ hỗ trợ `cmd` và `powershell`.
- Không dùng `--fast-workload` thì renderer giữ logic cũ.
- `--progress-every N` chỉ in tiến độ workload mỗi N operation.

## Capture Bằng tshark

Liệt kê interface:

```powershell
tshark -D
```

Capture SMB traffic tới server:

```powershell
tshark -i <INTERFACE_ID> -f "host 192.168.106.131 and tcp port 445" -w data\eval\pcaps\$RUN_ID.pcapng
```

Chạy workload ở terminal khác.

CMD:

```powershell
cmd /c data\eval\generated\workloads\cmd\$RUN_ID.cmd
```

PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File data\eval\generated\workloads\powershell\$RUN_ID.ps1
```

smbclient:

```bash
bash "data/eval/generated/workloads/smbclient/${RUN_ID}.sh"
```

Sau khi workload chạy xong, dừng `tshark` bằng `Ctrl+C`.

## Score Timeline

Score timeline với ground truth:

```powershell
.\.venv\Scripts\python.exe scripts\eval\score_timeline.py `
  --ground-truth data\eval\generated\ground_truth\$RUN_ID.jsonl `
  --timeline outputs\eval\timelines\${RUN_ID}_timeline.json `
  --out-dir outputs\eval\metrics\$RUN_ID `
  --time-before 1.0 `
  --time-after 3.0
```

`--time-before` và `--time-after` là cửa sổ match timestamp:

```text
ground_truth.start_time - time_before
đến
ground_truth.end_time + time_after
```

Nếu cửa sổ quá nhỏ, FN có thể tăng vì prediction đúng nhưng lệch thời gian. Nếu cửa sổ quá lớn, prediction của operation gần đó có thể bị match nhầm.

## Output

Timeline:

```text
outputs/eval/timelines/<RUN_ID>_timeline.json
```

Metrics:

```text
outputs/eval/metrics/<RUN_ID>/metrics.json
outputs/eval/metrics/<RUN_ID>/confusion_matrix.csv
outputs/eval/metrics/<RUN_ID>/confusion_matrix.json
outputs/eval/metrics/<RUN_ID>/matches.json
outputs/eval/metrics/<RUN_ID>/fp_debug.json
outputs/eval/metrics/<RUN_ID>/fn_debug.json
outputs/eval/metrics/<RUN_ID>/fp_fn_debug.json
```

Các chỉ số chính:

- precision
- recall
- F1
- confusion matrix
- FP/FN debug records

## Tổng Quan parse-pcap/FUSE

Module `parse-pcap` đọc PCAP/PCAPNG chứa SMB traffic, tái dựng cây thư mục/file, version nội dung và metadata. Kết quả có thể xuất ra JSON hoặc mount bằng FUSE để duyệt như filesystem.

Sample tái lập nhỏ 50 file nằm trong:

```text
sample/fuse_module_sample/README.md
sample/fuse_module_sample/pcaps/scale_0050_mixed.pcapng
sample/fuse_module_sample/ground_truth/scale_0050_mixed.json
sample/fuse_module_sample/expected_output.md
sample/fuse_module_sample/measure_runtime.sh
```

Xem hướng dẫn chạy đầy đủ trong `sample/fuse_module_sample/README.md`.

## Môi Trường parse-pcap/FUSE

Tạo virtual environment và cài dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

sudo apt install tshark fuse3
pcapfs --help
```

Nếu `pip install -r requirements.txt` lỗi encoding trên Linux/WSL, tạo requirements tạm:

```bash
iconv -f UTF-16LE -t UTF-8 requirements.txt > /tmp/smbmount_requirements.txt
pip install -r /tmp/smbmount_requirements.txt
```

Kiểm tra CLI:

```bash
python -m smbmount parse-pcap --help
python -m smbmount.benchmark_parsepcap.cli --help
```

## Option parse-pcap

Các option chính của lệnh `python -m smbmount parse-pcap <input_pcap> <output_json>`:

- `<input_pcap>`: file PCAP/PCAPNG đầu vào chứa SMB traffic.
- `<output_json>`: file JSON đầu ra chứa cây filesystem, metadata, event và content version đã tái dựng.
- `--timestamp-mode network`: dùng timestamp của packet để dựng timeline. Đây là mode dùng cho benchmark vì ổn định theo capture.
- `--timestamp-mode fs`: ưu tiên timestamp lấy từ metadata filesystem trong SMB response.
- `--timestamp-mode hybrid`: mode mặc định, kết hợp network timestamp và filesystem timestamp.
- `--reader streaming`: reader mặc định, đọc PCAP theo dòng để giảm memory khi file lớn.
- `--reader legacy`: reader cũ, dùng khi cần đối chiếu parser đời trước.
- `--snapshot-at <time>`: chỉ xuất snapshot filesystem tại một mốc thời gian cụ thể.
- `--snapshot-time-source network|fs`: chọn nguồn timestamp khi lọc snapshot.
- `--snapshot-include-deleted`: giữ cả file đã bị delete trong snapshot output.
- `--no-snapshot-include-deleted`: bỏ file đã bị delete khỏi snapshot output.
- `--fuse-mount <mountpoint>`: mount filesystem tái dựng bằng FUSE tại thư mục chỉ định; process sẽ tiếp tục chạy cho tới khi dừng bằng `Ctrl+C`.
- `--fuse-include-deleted`: hiển thị cả file đã bị delete trong FUSE view.
- `--fuse-allow-other`: cho user khác truy cập mountpoint, cần cấu hình FUSE của hệ thống cho phép `allow_other`.
- `--fuse-debug`: bật log debug của FUSE khi cần điều tra lỗi mount.

Các option chính của lệnh benchmark `python -m smbmount.benchmark_parsepcap.cli`:

- `--ground-truth`: file JSON ground truth sinh bởi workload generator.
- `--ours-json`: file JSON đầu ra từ `parse-pcap`.
- `--pcapfs-root`: thư mục mount của pcapFS để benchmark so sánh.
- `--scenario-dir`: thư mục gốc của scenario, ví dụ `bench_scale_0050_mixed`; dùng để strip path trước khi so khớp.
- `--out`: thư mục ghi metrics, confusion matrix và report.

Các option quan trọng của `sample/fuse_module_sample/measure_runtime.sh`:

- `--repeats`: số lần chạy lặp lại.
- `--out-dir`: thư mục ghi output.
- `--pcapfs-mount`: mountpoint tạm cho pcapFS.
- `--timestamp-mode`: mode timestamp dùng chung cho `parse-pcap` và pcapFS.
- `--reader`: reader của `parse-pcap`, thường dùng `streaming`.
- `--tool`: chọn `both`, `smbmount` hoặc `pcapfs`; mặc định `both`.
- `--case-file`: TSV chạy nhiều testcase, mỗi dòng gồm `case_id`, `files`, `pcap`, `ground_truth`, `scenario_dir`.

Các option của `scripts/eval_parsepcap/generate_scale_workload.py`:

- `--mount-root`: mountpoint SMB thật nơi workload sẽ tạo file/thư mục, ví dụ `/mnt/smbbench`.
- `--ground-truth`: đường dẫn JSON ground truth sẽ ghi ra.
- `--scenario-id`: ID logic của testcase, được dùng để sinh content deterministic và lưu metadata.
- `--scenario-dir`: thư mục gốc của testcase trong SMB share; script sẽ fail nếu thư mục này đã tồn tại để tránh lẫn dữ liệu cũ vào capture.
- `--files`: số file chính cần tạo. Với sample tái lập nhanh dùng `50`.
- `--seed`: seed random để kích thước file và phân bố dữ liệu ổn định giữa các lần chạy.
- `--dir-count`: số thư mục cấp 1 để rải file, giúp testcase có nhiều path khác nhau.
- `--min-size` và `--max-size`: khoảng kích thước file thường.
- `--large-every`: cứ mỗi N file sẽ tạo một file lớn; đặt `0` để tắt file lớn cho sample nhỏ.
- `--large-size`: kích thước file lớn khi `--large-every` bật.
- `--append-every`: cứ mỗi N file sẽ có thao tác append; đặt `0` để tắt append.
- `--overwrite-every`: cứ mỗi N file sẽ có thao tác overwrite một đoạn nội dung.
- `--truncate-every`: cứ mỗi N file sẽ có thao tác truncate làm ngắn file.
- `--rename-every`: cứ mỗi N file sẽ rename sang tên `_final.bin`.
- `--delete-every`: cứ mỗi N file sẽ delete sau khi tạo các version.
- `--delay`: thời gian nghỉ giữa các thao tác, giúp packet/timestamp tách nhau rõ hơn khi capture.

Các option/tham số dùng khi filter bằng `tshark`:

- `-r <file>`: đọc raw PCAP/PCAPNG đã capture.
- `-Y "smb || smb2 || tcp"`: display filter giữ lại traffic liên quan tới SMB/TCP để giảm noise khi benchmark.
- `-w <file>`: ghi PCAP/PCAPNG đã filter ra file mới.

## Chạy Nhanh parse-pcap

Parse sample PCAP ra JSON:

```bash
mkdir -p outputs/fuse_module_sample/manual

python -m smbmount parse-pcap \
  sample/fuse_module_sample/pcaps/scale_0050_mixed.pcapng \
  outputs/fuse_module_sample/manual/scale_0050_mixed.json \
  --timestamp-mode network
```

Mount FUSE:

```bash
python -m smbmount parse-pcap \
  sample/fuse_module_sample/pcaps/scale_0050_mixed.pcapng \
  outputs/fuse_module_sample/manual/scale_0050_mixed.json \
  --timestamp-mode network \
  --fuse-mount /tmp/smbmount_recon
```

Chạy benchmark tự động giữa `smbmount parse-pcap` và `pcapFS`:

```bash
sample/fuse_module_sample/measure_runtime.sh --repeats 5
```

Nếu chỉ muốn kiểm tra riêng SMBmount:

```bash
sample/fuse_module_sample/measure_runtime.sh --tool smbmount --repeats 1
```

Lệnh tạo lại workload, filter PCAP, chạy manual đầy đủ và `case-file` nhiều testcase nằm trong `sample/fuse_module_sample/README.md`.

## Expected Output parse-pcap

Expected output đầy đủ của sample được lưu tại:

```text
sample/fuse_module_sample/expected_output.md
```

Kết quả đối chiếu của sample `scale_0050_mixed`:

| Tool | strict_path_content TP/FP/FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| smbmount parse-pcap | 90/0/0 | 1.0000 | 1.0000 | 1.0000 |
| pcapFS | 80/13/10 | 0.8602 | 0.8889 | 0.8743 |

## Output parse-pcap

Các file output chính:

```text
outputs/fuse_module_sample/manual/scale_0050_mixed.json
outputs/fuse_module_sample/manual/benchmark/ours_metrics.json
outputs/fuse_module_sample/manual/benchmark/pcapfs_metrics.json
outputs/fuse_module_sample/manual/benchmark/comparison_metrics.json
outputs/fuse_module_sample/manual/benchmark/comparison_report.md
outputs/fuse_module_sample/runtime_metrics.csv
```

## Cấu Trúc Chính

```text
smbmount/
  cli.py                 CLI entrypoint
  parser/pcap_reader.py  PCAP/PCAPNG SMB extraction
  scf/
    detector.py          SCF rule matching and progress reporting
    loader.py            Rule loader for JSON/TSV/built-in rules
    normalize.py         Semantic feature normalization
    renderer.py          Optional Rich table renderer
    timeline.py          Timeline assembly

rules/
  cmd_rules.json
  powershell_rules.json
  smbclient_rules.json

scripts/eval/
  generate_operation_scale.py
  render_cmd.py
  render_powershell.py
  render_smbclient.py
  score_timeline.py

sample/fuse_module_sample/
  pcaps/scale_0050_mixed.pcapng
  ground_truth/scale_0050_mixed.json
  README.md
  expected_output.md
  measure_runtime.sh

outputs/eval/
  timelines/
  metrics/
```

## Ghi Chú Thực Nghiệm

- `cmd` và `powershell` nên dùng mapped drive, ví dụ `Z:`.
- `smbclient` chạy tốt hơn trên Linux/WSL với auth file.
- Với scale lớn, không dùng `--print-table` khi dựng SCF timeline.
- Với workload lớn, dùng `--fast-workload --progress-every 100` cho CMD/PowerShell.
- PCAP và generated workload thường lớn; chỉ commit khi cần chia sẻ kết quả cụ thể.
