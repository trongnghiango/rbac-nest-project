## Tại sao đã có bảng position ma phai tạo thêm bảng location để làm gì?

Rất nhiều người khi thiết kế Database thường bị nhầm lẫn và gộp chung hai khái niệm này lại với nhau.

Để trả lời ngắn gọn:
*   Bảng **`positions` (và `org_units`)** là cấu trúc **LUẬN LÝ (Logical)**: Xác định nhân viên đó làm *nghiệp vụ gì* và *báo cáo cho ai*.
*   Bảng **`locations`** là vị trí **VẬT LÝ (Physical/Geographical)**: Xác định nhân viên đó *ngồi làm việc ở đâu* (Tòa nhà nào, thành phố nào).

Hãy tiếp tục dùng ẩn dụ "Ngôi nhà": `org_units` là các phòng trong nhà, `positions` là cái ghế trong phòng, còn **`locations` chính là việc ngôi nhà đó được xây ở Hà Nội hay TP.HCM**.

Dưới đây là giải thích chi tiết tại sao phải tách riêng bảng `locations` và nó giải quyết bài toán Enterprise (quy mô lớn) như thế nào.

---

### 1. TẠI SAO KHÔNG GỘP CHUNG `LOCATIONS` VÀO `ORG_UNITS` HAY `POSITIONS`?

#### Ví dụ SAI lầm kinh điển (Lỗi thiết kế nghiệp dư):
Nhiều công ty tạo "Chi nhánh Hà Nội" và "Chi nhánh TP.HCM" ngay trong bảng Phòng ban (`org_units`). 
*   **Hệ lụy:** Nhân viên Sales ở Hà Nội sẽ được gắn vào phòng "Chi nhánh Hà Nội". Khi Giám đốc Kinh doanh (Sales Director) muốn kéo báo cáo doanh thu của toàn bộ khối Sales, hệ thống sẽ không hiểu Nhân viên Sales HN và Sales HCM thuộc cùng một khối nghiệp vụ, vì họ đang nằm ở hai "Phòng ban" khác nhau.

#### Kiến trúc ĐÚNG (Tách biệt Logical và Physical):
Một vị trí (Position) như "Nhân viên Sales" có thể có 50 người ngồi. Trong đó 20 người ngồi ở Hà Nội (`locationId = 1`) và 30 người ngồi ở TP.HCM (`locationId = 2`). Tất cả 50 người này đều thuộc Phòng Sales (`org_units`), nhưng khác nhau về vị trí địa lý.

---

### 2. BẢNG `LOCATIONS` ĐƯỢC DÙNG ĐỂ LÀM GÌ TRONG THỰC TẾ?

Bảng `locations` đóng vai trò cốt lõi trong 3 phân hệ cực kỳ quan trọng của HR:

#### A. Phân hệ Chấm công (Time & Attendance)
*   **Bài toán:** Khi nhân viên dùng App ERP trên điện thoại để chấm công, làm sao biết họ đang đứng ở công ty hay đang gian lận chấm công ở quán cà phê?
*   **Giải pháp:** Bảng `locations` sẽ lưu tọa độ GPS, địa chỉ IP Wifi hoặc mã máy chấm công vân tay của văn phòng đó. Khi nhân viên có `locationId = 1` (Hà Nội) bấm chấm công, hệ thống sẽ đối chiếu tọa độ điện thoại với tọa độ của `locationId = 1` để hợp lệ hóa.

#### B. Phân hệ Lương, Thuế & Bảo hiểm (Payroll & Compliance)
*   **Bài toán:** Theo luật lao động Việt Nam, Mức lương tối thiểu vùng ở Vùng 1 (Hà Nội, TP.HCM) cao hơn Vùng 3 (một số tỉnh lẻ). Mức đóng Bảo hiểm xã hội tối thiểu cũng khác nhau.
*   **Giải pháp:** Nhân viên ở vị trí giống hệt nhau, cấp bậc giống hệt nhau, nhưng đóng BHXH dựa trên `locationId`. 

#### C. Phân hệ Quản lý Hành chính (Admin/Facility)
*   **Bài toán:** Trưởng phòng hành chính ở văn phòng TP.HCM cần biết văn phòng mình có bao nhiêu người để đặt mua cơm trưa, đăng ký vé gửi xe, tính toán diện tích thuê văn phòng.
*   **Giải pháp:** Lọc bảng `employees` theo `locationId = 2` (TP.HCM), bất kể họ thuộc phòng ban (Org Unit) nào.

---

### 3. MÔ PHỎNG LUỒNG DỮ LIỆU THỰC TẾ BẰNG BẢNG

Hãy xem câu chuyện của **Công ty STAX có đội ngũ Lập trình viên phân bổ ở cả 2 miền**.

**1. Khởi tạo dữ liệu Vị trí vật lý (Bảng `locations`)**
| id | code | name | address | timezone |
|---|---|---|---|---|
| 1 | HN-HQ | Trụ sở Hà Nội | Tòa nhà Lotte, Liễu Giai | GMT+7 |
| 2 | HCM-BR | Chi nhánh TP.HCM | Bitexco, Quận 1 | GMT+7 |
| 3 | REMOTE | Làm việc từ xa | Bất kỳ đâu | null |

**2. Khởi tạo cái "Ghế" luận lý (Bảng `positions`)**
| id | code | name | orgUnitId (Phòng ban) |
|---|---|---|---|
| **100** | DEV-MID | Lập trình viên Middle | Phòng IT (ID: 5) |

**3. Hồ sơ nhân sự (Bảng `employees`)**
*HR tuyển 2 Lập trình viên. Họ ngồi chung 1 loại ghế (Position 100), nhưng ở 2 nơi khác nhau.*

| id | fullName | positionId (Nghiệp vụ) | **locationId (Vật lý)** | managerId (Sếp) |
|---|---|---|---|---|
| 1 | Nguyễn Văn A | **100** (Dev Middle) | **1** (Hà Nội) | 99 (Sếp IT) |
| 2 | Trần Thị B | **100** (Dev Middle) | **2** (TP.HCM) | 99 (Sếp IT) |

#### HỆ THỐNG SẼ HOẠT ĐỘNG NHƯ SAU:

1.  **Về mặt Quản lý (Reporting):** Ông Sếp IT (ID: 99) mở biểu đồ tổ chức ra, thấy cả A và B đều báo cáo cho mình, cùng nằm trong "Phòng IT". Dữ liệu này lấy từ `positionId`.
2.  **Về mặt Chấm công:** Khi Trần Thị B tới tòa nhà Bitexco bắt Wifi văn phòng HCM, hệ thống đối chiếu với `locationId = 2` và ghi nhận "Chấm công thành công". Nếu B bay ra Hà Nội công tác và quẹt thẻ ở tòa nhà Lotte (`locationId = 1`), hệ thống sẽ báo cảnh báo (hoặc nhân viên phải tạo đơn xin "Chấm công khác địa điểm").
3.  **Về mặt Nghỉ lễ:** Văn phòng HCM có thể cho nghỉ ngày giải phóng miền Nam 30/4 kéo dài hơn, hoặc có thông báo cúp điện riêng cho Tòa nhà Bitexco. HR chỉ cần chọn tính năng: *"Gửi thông báo đẩy (Notification) đến tất cả nhân viên có `locationId = 2`"*. Ông Nguyễn Văn A ở HN sẽ không bị nhận nhầm thông báo cúp điện này.

### TƯ VẤN CHO KHÁCH HÀNG
 
> *"Thiết kế tách bạch `positions` (nghiệp vụ) và `locations` (địa lý) cho phép Công ty (Tập đoàn) dễ dàng mở rộng thành công ty đa quốc gia, đa chi nhánh. Công ty có thể quản lý 1 phòng IT nhưng nhân sự rải rác ở Việt Nam, Singapore, Mỹ mà vẫn tính toán lương thưởng, chấm công chính xác theo luật pháp của từng địa phương, không hề bị rối loạn cấu trúc báo cáo quản trị."*