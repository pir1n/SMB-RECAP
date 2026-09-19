# File Explorer Ground Truth và Conservative SCF Policy

## 1. Mục tiêu

Xây dựng và đánh giá rule SCF cho thao tác Windows File Explorer, đồng thời giảm FP do các hoạt động nền như tự động enumerate thư mục, preview và đọc metadata.

Rule conservative chỉ được xây dựng và kiểm tra bằng:

- `File_explorer_pcap/Dev_Train_rule_file_explorer.pcapng`
- `File_explorer_pcap/ground_truth-Dev_Train_rule_file_explorer.jsonl`

Không sử dụng `file_explorer_50_action.pcapng` hoặc `ground_truth-50.jsonl` để chỉnh rule.

## 2. Quy trình tạo PCAP và ground truth

Quy trình thu thập dữ liệu là plan-driven và có người thực nghiệm:

1. Viết `plan.jsonl` trước khi capture. Mỗi record gồm `op_id`, loại thao tác, đường dẫn nguồn và đường dẫn đích; chưa chứa thời gian hoặc kết quả.
2. Bắt đầu capture lưu lượng SMB thành PCAP/PCAPNG.
3. Một chương trình lần lượt hiển thị từng tác vụ trong plan. Người thực nghiệm thực hiện đúng tác vụ đang được hiển thị bằng Windows Explorer.
4. Chương trình ghi `start_time`, `end_time` và kết quả `success/failed` vào `ground_truth.jsonl`.
5. Dừng capture, chạy SCF trên PCAP và dùng ground truth để score timeline.

Ưu điểm của quy trình này là danh sách tác vụ được xác định trước, thời gian thực hiện được ghi theo từng operation và thao tác vẫn do người thật thực hiện bằng Explorer. Tuy nhiên, PCAP còn chứa SMB I/O nền do Explorer tự phát sinh trong lúc cửa sổ đang mở.

## 3. Thành phần ground truth DEV

Ground truth gồm 69 thao tác:

| Loại thao tác | Số lượng |
|---|---:|
| Copy từ share | 5 |
| Copy lên share | 8 |
| Copy trong share | 3 |
| Tạo file | 3 |
| Tạo folder | 8 |
| Xóa file | 6 |
| Sửa nội dung | 6 |
| Move trong share | 5 |
| Rename | 4 |
| Navigate folder | 9 |
| Navigate tới share | 2 |
| Refresh folder | 3 |
| Mở file | 4 |
| Xem properties | 3 |

Ground truth không có action riêng cho preview hoặc background metadata read. Đây là I/O do Explorer và các handler của Windows tự phát sinh, không phải tác vụ độc lập trong plan.

## 4. Lý do xuất hiện FP

Ở tầng SMB, các thao tác sau có dấu vết tương đương hoặc rất giống nhau:

- Navigate/refresh do người dùng và background enumeration đều dùng `QUERY_DIRECTORY`.
- Mở file thật, preview, thumbnail và một số metadata handler đều có thể dùng `CREATE(read) → READ`.
- `QUERY_INFO` có thể xuất hiện khi xem properties nhưng cũng được Explorer gọi tự động để dựng giao diện.

Do PCAP không chứa sự kiện click, phím bấm hoặc PID/process phía client, detector không thể xác định chắc chắn SMB request nào bắt nguồn trực tiếp từ người dùng.

## 5. Conservative policy

Policy conservative nằm tại:

`SMBmount/rules/file_explorer_conservative_rules.json`

Policy chỉ xuất các behavior có bằng chứng SMB mạnh:

- create file/directory;
- upload/copy;
- download;
- edit/write;
- delete;
- rename/move.

Policy không xuất:

- `directory_listing`, nhằm tránh FP từ automatic enumerate/refresh;
- `read_file/view_properties`, nhằm tránh FP từ preview và metadata read.

Đây là lựa chọn ưu tiên precision. Nó không khẳng định các thao tác bị bỏ qua không xảy ra, mà chỉ cho biết SMB PCAP không đủ bằng chứng để quy chúng cho một user action cụ thể.

## 6. Kết quả trên DEV

| Policy score | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Strict | 48 | 1 | 21 | 97.96% | 69.57% | 81.36% |
| Relaxed cache observability | 48 | 1 | 16 | 97.96% | 75.00% | 84.96% |

Các behavior được policy giữ lại đều đạt recall 100% trên DEV:

| Behavior | TP | FN |
|---|---:|---:|
| Create directory | 8 | 0 |
| Create file | 3 | 0 |
| Upload/copy | 11 | 0 |
| Download | 5 | 0 |
| Edit/write | 6 | 0 |
| Delete | 6 | 0 |
| Rename/move | 9 | 0 |

## 7. Giải thích FN

21 FN strict đều đến từ hai nhóm bị conservative policy chủ động loại bỏ:

- 14 `directory_listing`: 9 navigate folder, 2 navigate tới share và 3 refresh folder;
- 7 `read_file`: 4 mở file và 3 xem properties.

Không có FN strict ở create, upload/copy, download, edit, delete hoặc rename/move.

Trong relaxed scoring, 5 listing không có `QUERY_DIRECTORY` trong đúng cửa sổ ground truth được đánh dấu `not_observable` thay vì tính FN. Vì vậy relaxed còn 16 FN, gồm 9 listing có evidence và 7 open/properties bị policy bỏ qua.

## 8. Kết luận và gap

Conservative policy giảm mạnh FP và phù hợp khi timeline cần độ tin cậy cao. Đổi lại, nó không thể tuyên bố đầy đủ các user action liên quan đến navigate, refresh, open và properties.

Để vừa giữ precision cao vừa khôi phục recall cho các action mơ hồ, cần bổ sung telemetry phía client như ETW, Procmon, Windows Audit hoặc một agent ghi process/PID và thời gian tương tác. SMB PCAP vẫn là nguồn xác nhận hành vi filesystem trên mạng; telemetry endpoint cung cấp bằng chứng về ứng dụng và ý định người dùng.

Kết quả trong báo cáo này là kết quả DEV, không phải kết quả hold-out. Policy conservative chưa được kiểm định trên một hold-out mới hoàn toàn chưa từng được quan sát.
