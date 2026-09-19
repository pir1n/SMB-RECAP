# File Explorer: FKIE SCF so với SMBmount

## Thiết lập

Rule của hai hệ thống chỉ được xây dựng từ:

- `Dev_Train_rule_file_explorer.pcapng`
- `ground_truth-Dev_Train_rule_file_explorer.jsonl`

Rule FKIE dùng cơ chế hash sequence nguyên bản của tác giả và được lưu tại `SCF/rules/explorer-dev-rules.tsv`. Không sửa detector lõi của FKIE. Output text của FKIE được chuyển sang cùng taxonomy behavior và cùng chính sách conservative bằng `SMBmount/scripts_evaluation/scf/normalize_fkie_explorer_output.py`.

Hai hệ thống đều không score navigate/refresh/open/properties trong conservative policy, vì SMB không phân biệt chắc chắn user action với enumerate/preview/metadata nền.

Rule và adapter được đóng băng bằng SHA-256 trong `SCF/rules/explorer-dev-freeze-20260906.md` trước khi chạy bộ 50 actions. Không sửa rule theo kết quả bộ kiểm tra.

## Kết quả DEV

| Implementation | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| FKIE + DEV rules | 48 | 1 | 21 | 97.96% | 69.57% | 81.36% |
| SMBmount conservative | 48 | 1 | 21 | 97.96% | 69.57% | 81.36% |

Kết quả DEV bằng nhau. Toàn bộ 21 FN là 14 directory listing và 7 open/properties bị policy chủ động không xuất.

## Kết quả trên `file_explorer_50_action.pcapng`

| Implementation | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| FKIE + frozen DEV rules | 39 | 16 | 11 | 70.91% | 78.00% | **74.29%** |
| SMBmount + frozen conservative rules | 34 | 21 | 16 | 61.82% | 68.00% | **64.76%** |

### Theo behavior

| Behavior | FKIE TP/FP/FN | SMBmount TP/FP/FN |
|---|---:|---:|
| Create directory | 7 / 2 / 2 | 7 / 2 / 2 |
| Upload/copy | 14 / 3 / 2 | 14 / 13 / 2 |
| Download | 2 / 3 / 1 | 2 / 1 / 1 |
| Delete | 3 / 1 / 0 | 3 / 1 / 0 |
| Rename/move | 13 / 7 / 5 | 8 / 4 / 10 |
| Directory listing | 0 / 0 / 1 | 0 / 0 / 1 |

## Nhận xét

FKIE tốt hơn 9.53 điểm F1 trên bộ 50 actions. Chênh lệch chủ yếu do rule hash sequence của FKIE tổng quát tốt hơn cho rename/move: FKIE bắt 13/18, SMBmount bắt 8/18. FKIE cũng ít FP upload/copy hơn sau khi adapter gộp ba pha download nguồn, upload đích tạm và rename đích thành một copy trong share.

SMBmount có precision download tốt hơn (66.67% so với 40.00%) và ít FP rename hơn, nhưng recall rename thấp. Hai hệ thống bằng nhau ở create directory, delete và recall của upload/download.

Kết quả không chứng minh FKIE luôn tốt hơn: đây là một capture kiểm tra, và policy mới được phát triển sau khi bộ 50 actions từng tồn tại trong workspace. Việc không sửa rule sau freeze ngăn tuning trực tiếp trong lần chạy này, nhưng bằng chứng tổng quát mạnh hơn vẫn cần một hold-out mới chưa từng được quan sát.

## Artifact

- FKIE rule: `SCF/rules/explorer-dev-rules.tsv`
- FKIE raw output: `File_explorer_pcap/fkie_explorer_holdout50_output.txt`
- FKIE timeline/score: `File_explorer_pcap/fkie_explorer_holdout50_timeline.json`, `File_explorer_pcap/fkie_explorer_holdout50_score/`
- SMBmount timeline/score: `File_explorer_pcap/smbmount_explorer_conservative_holdout50_timeline.json`, `File_explorer_pcap/smbmount_explorer_conservative_holdout50_score/`
