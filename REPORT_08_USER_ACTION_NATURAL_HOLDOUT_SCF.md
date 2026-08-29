# User_action: natural hold-out và baseline FKIE SCF

## Phạm vi

Đánh giá này chỉ xét module SCF hiện tại của `SMBmount` và implementation SCF
chính thức của FKIE. Bản thử nghiệm behavior-agnostic và pcapFS không nằm trong
kết quả dưới đây.

`User_action.pcapng` là workload tự nhiên: người dùng tự gõ lệnh CMD trong nhiều
phiên, không dùng script sinh operation. Các log bị tách do lỗi capture đã được
ghép thành 183 command record, sau đó chuẩn hóa thành 110 action SMB có thể chấm.
PCAP được giới hạn theo share bằng `SessionId:TreeId = 65970697666577:1` để loại
traffic SMB nền. Bộ này không được dùng để thiết kế hoặc tune rule; các sửa đổi
rule/detector trước đó được thực hiện trên dữ liệu DEV.

## Phương pháp

Hai detector chạy trên cùng `User_action.pcapng`:

- SMBmount dùng `rules/cmd_rules.json`, parser và detector hiện tại.
- FKIE chạy source chính thức trong folder `SCF` với `cmd-rules.tsv`, không sửa
  rule của tác giả và không chuyển rule SMBmount sang FKIE.
- Cả hai timeline được chấm bởi cùng `score_timeline.py`, cùng ground truth và
  cửa sổ thời gian `[-1 s, +3 s]`.

Việc đưa FKIE vào thí nghiệm đáp ứng yêu cầu có baseline SCF chính thức. Nó không
thay thế benchmark filesystem với pcapFS: pcapFS và SCF giải quyết hai bài toán
khác nhau nên không so sánh chéo metric hoặc runtime.

## Kết quả

| Detector | Dự đoán | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| SMBmount strict | 109 | 82 | 27 | 28 | 0,7523 | 0,7455 | 0,7489 |
| FKIE strict | 67 | 62 | 5 | 48 | 0,9254 | 0,5636 | 0,7006 |

SMBmount có recall và F1 cao hơn, đặc biệt phát hiện các nhóm mà FKIE CMD không
trả ra trong capture này: append, upload, overwrite và rename. FKIE thận trọng
hơn nên precision cao hơn nhưng bỏ sót nhiều action hơn. Hai output không giống
nhau: chỉ có 42 event khớp semantics trực tiếp; SMBmount có 67 event riêng và
FKIE có 25 event riêng, phần lớn khác biệt liên quan directory listing.

## Kiểm định strict và relaxed

Scorer được chạy ba chế độ riêng, không gộp các policy:

| Detector | Policy | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| SMBmount | Strict | 82 | 27 | 28 | 0,7523 | 0,7455 | 0,7489 |
| SMBmount | Relaxed chỉ tương thích nhãn: `overwrite_file` ↔ `write_file` | 82 | 27 | 28 | 0,7523 | 0,7455 | 0,7489 |
| SMBmount | Relaxed nhãn + cached-listing observability | 82 | 27 | 14 | 0,7523 | 0,8542 | 0,8000 |
| FKIE | Strict | 62 | 5 | 48 | 0,9254 | 0,5636 | 0,7006 |
| FKIE | Relaxed chỉ tương thích nhãn: `overwrite_file` ↔ `write_file` | 62 | 5 | 48 | 0,9254 | 0,5636 | 0,7006 |
| FKIE | Relaxed nhãn + cached-listing observability | 49 | 18 | 47 | 0,7313 | 0,5104 | 0,6012 |

Alias overwrite/write không làm thay đổi kết quả của capture này; vì vậy không
có trường hợp `overwrite_file` được báo đúng chỉ nhờ dự đoán `write_file`.
F1 0,8000 của SMBmount đến từ việc loại 14 ground-truth listing không có
`QUERY_DIRECTORY` trong PCAP cùng cửa sổ, không phải từ alias overwrite/write.

FKIE giảm ở chế độ cached-aware vì 13 listing từng khớp ground truth nay trở
thành FP sau khi các ground-truth listing không quan sát được bị loại. Đây là hệ
quả của policy observability, không phải FKIE thay đổi output.

## Thời gian theo công đoạn

| Công đoạn | SMBmount | FKIE | Có thể so sánh trực tiếp? |
|---|---:|---:|---|
| PCAP → timeline/output: parse + hash + rule matching + export | 2,4171 s | 8,2977 s | Có, cùng đầu vào và cùng mục tiêu end-to-end |
| Scoring cùng scorer | 0,1900 s | 0,1290 s | Có |
| Mount filesystem | N/A | N/A | Không thuộc SCF |
| Export filesystem | N/A | N/A | Không thuộc SCF |
| Parse riêng | Chưa instrument độc lập | Chưa instrument độc lập | Chưa |
| Hash riêng | Chưa instrument độc lập | Chưa instrument độc lập | Chưa |
| Export timeline riêng | Chưa instrument độc lập | Chưa instrument độc lập | Chưa |

Trên lần đo này, pipeline SCF end-to-end của SMBmount nhanh hơn FKIE khoảng
`3,43×`. Chỉ tỷ lệ end-to-end này hợp lệ; không được diễn giải thành “parse nhanh
hơn 3,43×” hoặc “hash nhanh hơn 3,43×”. Scoring FKIE nhanh hơn khoảng `1,47×`,
nhưng scoring nhỏ hơn nhiều so với pipeline detector. Đây mới là một lần timing,
chưa đủ để báo trung bình, độ lệch chuẩn hoặc kiểm định thống kê.

## Những phần đã cải thiện trước hold-out

Các thay đổi được phát triển từ dữ liệu DEV, trước khi đánh giá `User_action`:

- parser streaming và TCP reassembly để tránh nạp toàn PCAP bằng `rdpcap()`;
- ghép request/response và handle bằng SessionId, TreeId, FileId và generation;
- scope chính xác theo `SessionId:TreeId`, tránh SYSVOL/NETLOGON và SMB nền;
- sửa semantics create/overwrite/upload/download/delete, chống duplicate event;
- scorer báo strict và relaxed riêng; cached listing chỉ được loại khi raw dump
  thực sự không có `QUERY_DIRECTORY` trong đúng run/scope/cửa sổ thời gian.

Không có rule nào được tune dựa trên mismatch của `User_action`.

## Khó khăn và GAP còn lại

- Directory cache là giới hạn quan sát: `dir` có thể được phục vụ từ cache phía
  client và không sinh `QUERY_DIRECTORY`; PCAP không thể khôi phục action không
  đi qua mạng. Ngược lại, `cd` hoặc tiến trình hỗ trợ có thể sinh listing thật,
  tạo FP khi ground truth chỉ ghi command người dùng.
- Ground truth ghi ý định cấp command, còn SCF thấy SMB I/O. Một command lỗi vẫn
  có thể tạo I/O phụ; upload/download cũng có thể gồm nhiều handle. Hai tầng này
  chưa có mô hình causal hoàn chỉnh.
- FKIE là rule theo application và lần này chỉ dùng CMD rules; kết quả không cho
  phép tuyên bố về PowerShell, Explorer hoặc mọi ứng dụng SMB.
- Hold-out hiện chứng minh được workload tự nhiên chưa dùng để thiết kế rule,
  nhưng mới có một capture và một cấu hình lab. Chưa đủ để tuyên bố tổng quát qua
  nhiều Windows build, server, network condition và user.
- Timing chưa tách riêng parse/hash/matching/export trong từng implementation.
  Cần thêm instrumentation giống nhau, chạy warm-up rồi lặp tối thiểu 10 lần và
  báo median, mean, standard deviation, p95 trước khi kết luận hiệu năng.
- Relaxed cached-listing làm thay đổi tập ground truth có thể chấm; metric này
  phải luôn được trình bày cạnh strict, không được dùng thay thế strict.
