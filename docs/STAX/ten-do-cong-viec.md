Để một mình "cân" một hệ thống Enterprise khổng lồ mà không bị trễ deadline hay stress đến mức kiệt sức, bí quyết duy nhất là **Kỷ luật thép trong việc chia nhỏ công việc (Work Breakdown Structure - WBS)** và **Đóng gói tính năng theo từng Sprint (2 tuần/lần)**.

Dưới đây là **Bảng Tiến độ thi công chi tiết (Master Schedule)** được thiết kế đặc biệt dành cho Lập trình viên độc lập (Solo Developer). Lịch trình này kéo dài **22 tuần (khoảng 5.5 tháng)**, đã bao gồm cả "thời gian đệm" (Buffer time) để bạn sửa bug, nghỉ ngơi, hoặc phòng hờ lúc ốm đau.

---

### TỔNG QUAN KHUNG THỜI GIAN (FRAMEWORK)
*   **Mô hình:** Agile / 2 tuần = 1 Sprint.
*   **Thứ 6 của tuần cuối Sprint:** Họp Demo Online với STAX, chốt tính năng, bàn giao Source Code lên Git.
*   **Nguyên tắc cốt lõi:** Làm BE (Backend) trước, FE (Frontend) sau. Hoàn thiện tính năng nào là khóa (Lock) tính năng đó lại, không sửa đổi lan man.

---

### GIAI ĐOẠN 1: CORE, HRM CƠ BẢN, CRM & FINOTE (14 Tuần - 7 Sprints)

#### 🚀 Sprint 1 (Tuần 1 - 2): Dọn dẹp & Khởi tạo Nền tảng
*Mục tiêu: Đưa hệ thống Core lên chạy thực tế, chứng minh năng lực ngay lập tức.*
*   **Backend (BE):**
    *   Dọn dẹp tàn dư code cũ (Xóa Dental module, comment Chatbot lại).
    *   Setup Docker, Database Postgres, cấu hình Drizzle migrate.
    *   Hoàn thiện API Đăng nhập, Đổi mật khẩu, Quản lý User và Role (Phân quyền).
*   **Frontend (FE):**
    *   Setup Project (Khuyến nghị mua/dùng Template Admin như *Ant Design Pro, Metronic* để tiết kiệm 50% thời gian).
    *   Giao diện Login, Quản lý User, Giao diện Cấp quyền (Ma trận Role-Permission).
*   **🎁 Cuối Sprint Demo:** Khách hàng thấy được màn hình đăng nhập, tạo user và phân quyền cực nhanh.

#### 🚀 Sprint 2 (Tuần 3 - 4): HRM - Sơ đồ tổ chức & Hồ sơ nhân sự
*Mục tiêu: Dựng cấu trúc xương sống của công ty.*
*   **BE:** API CRUD Phòng ban (Cấu trúc Materialized Path), API CRUD Chức danh, Vị trí. API Quản lý nhân viên (Employees).
*   **FE:** Vẽ giao diện Sơ đồ cây phòng ban (Tree/OrgChart). Màn hình Danh sách nhân viên, Form thêm mới nhân viên.
*   **🎁 Cuối Sprint Demo:** Thêm phòng ban, chuyển nhân sự từ phòng này sang phòng khác.

#### 🚀 Sprint 3 (Tuần 5 - 6): File Storage (Google Drive) & CRM Leads
*Mục tiêu: Giải quyết bài toán Dữ liệu cứng & Quản lý Khách hàng tiềm năng.*
*   **BE:**
    *   Tạo `GoogleDriveAdapter`, kết nối Service Account.
    *   Tạo bảng `attachments`. API Upload/Download file.
    *   API Quản lý Leads (Kanban board).
*   **FE:** Tích hợp component Upload File. Màn hình Kanban kéo thả Leads (Từ "Tiếp cận" -> "Thương lượng" -> "Chốt").
*   **🎁 Cuối Sprint Demo:** Khách hàng up thử 1 file PDF lên phần mềm, mở Google Drive ra thấy file nằm đúng thư mục.

#### 🚀 Sprint 4 (Tuần 7 - 8): Quản lý Hợp đồng & Báo giá
*Mục tiêu: Chốt Sales.*
*   **BE:**
    *   Bảng Contracts (Hợp đồng) liên kết với Organization.
    *   Tạo API Cảnh báo hết hạn hợp đồng (Dùng Cronjob rà soát mỗi đêm).
    *   API Tạo Báo giá (Quotes) & Xuất ra file PDF.
*   **FE:** Màn hình danh sách Hợp đồng, Hiển thị nhãn cảnh báo (Đỏ/Vàng) khi sắp hết hạn. Màn hình tạo Báo giá.
*   **🎁 Cuối Sprint Demo:** In thử 1 Báo giá ra file PDF trực tiếp từ hệ thống.

#### 🚀 Sprint 5 (Tuần 9 - 10): Luồng duyệt Finote (Trọng tâm)
*Mục tiêu: Tự động hóa quy trình nội bộ của STAX.*
*   **BE:**
    *   API CRUD Finote.
    *   **Cronjob:** Code logic kiểm tra định kỳ (Quá 3 ngày không ai duyệt -> Tự động chuyển status thành APPROVED).
*   **FE:** Màn hình lên Finote cho Staff. Màn hình "Chờ Duyệt" cho Leader (Có nút Approve/Reject).
*   **🎁 Cuối Sprint Demo:** Tạo 1 Finote, log vào tài khoản Sếp để bấm duyệt.

#### 🚀 Sprint 6 (Tuần 11 - 12): Tích hợp tổng thể & Fix Bug nội bộ
*Lưu ý: Không code tính năng mới ở Sprint này.*
*   Đây là khoảng thời gian "thở" cho bạn.
*   Bạn sẽ tự test (Unit Test / Manual Test) các luồng liên kết.
*   Tối ưu hóa UI/UX, responsive (điện thoại/tablet).

#### 🚀 Sprint 7 (Tuần 13 - 14): UAT Giai đoạn 1 & Golive
*   Triển khai (Deploy) hệ thống lên máy chủ thật của STAX (hoặc VPS do bạn setup hộ).
*   Đào tạo STAX sử dụng.
*   Khách hàng dùng thử (UAT) và báo bug. Bạn nhận list bug và sửa.
*   **KÝ NGHIỆM THU GIAI ĐOẠN 1 -> NHẬN TIỀN ĐỢT 2.**

---

### GIAI ĐOẠN 2: TASK MANAGEMENT, LƯƠNG & AUDIT LOG (8 Tuần - 4 Sprints)

#### 🚀 Sprint 8 (Tuần 15 - 16): Hệ thống Audit Log & API Chấm công
*Mục tiêu: Giải quyết bài toán bảo mật theo chuẩn Enterprise.*
*   **BE:**
    *   Triển khai **Database Level Interception** (Ghi đè hàm update trong DrizzleBaseRepository).
    *   Setup EventBus đẩy log xuống Postgres JSONB.
    *   Viết API (Webhook) nhận dữ liệu check-in/out từ máy chấm công.
*   **FE:** Màn hình xem Audit Log (Chỉ dành cho Super Admin). Màn hình xem lịch sử chấm công.
*   **🎁 Cuối Sprint Demo:** Thay đổi lương 1 nhân viên -> Mở Audit Log ra thấy hiển thị rõ `Dữ liệu cũ: 10tr` -> `Dữ liệu mới: 12tr`.

#### 🚀 Sprint 9 (Tuần 17 - 18): Task Management (Quản lý công việc)
*Mục tiêu: Số hóa giao việc nội bộ.*
*   **BE:** CRUD Tasks, Gán người thực hiện (Assignees), Deadline, API bắn Notification khi có Task mới hoặc sắp trễ hạn.
*   **FE:** Màn hình Bảng công việc (Board/List), Cập nhật trạng thái (Todo, Doing, Done). Nhận thông báo.
*   **🎁 Cuối Sprint Demo:** Sếp giao việc -> Nhân viên nhận được Notification (Chuông) góc màn hình.

#### 🚀 Sprint 10 (Tuần 19 - 20): Tính Lương (Payroll Formula)
*Mục tiêu: Khép lại quy trình HRM.*
*   **BE:** Parser tính lương (Đọc công thức động). Chốt bảng lương cuối tháng.
*   **FE:** Màn hình cấu hình Công thức lương. Màn hình Bảng lương tổng, Phiếu lương cá nhân (Payslip).
*   **🎁 Cuối Sprint Demo:** Bấm nút "Chốt Lương Tháng 10" -> Tự động tính ra số tiền.

#### 🚀 Sprint 11 (Tuần 21 - 22): UAT Giai đoạn 2 & Bàn giao toàn bộ
*   Khách hàng test toàn bộ hệ thống (GĐ1 + GĐ2 chạy cùng nhau).
*   Bạn fix các bug cuối cùng.
*   Đóng gói Source code, API Docs, hướng dẫn Deploy.
*   **KÝ NGHIỆM THU TỔNG THỂ -> NHẬN TIỀN CÒN LẠI.**

---

### 💡 4 BÍ QUYẾT QUẢN LÝ DỰ ÁN CHO SOLO-DEV (Để không vỡ trận)

1. **Khóa Yêu Cầu (Scope Freeze):** Đầu mỗi Sprint, bạn gửi STAX danh sách: *"2 tuần này em sẽ làm tính năng A, B, C"*. Nếu giữa Sprint khách nhắn: *"Em ơi làm thêm nút này"*, bạn phải trả lời: *"Dạ em ghi nhận, em sẽ đưa nó vào Sprint sau nhé, Sprint này em đã khóa tính năng để đảm bảo tiến độ"*.
2. **Timeboxing Hàng Ngày:** Đừng code từ sáng đến đêm mờ mắt. Hãy chia:
    *   Sáng (8h - 12h): Chỉ viết Backend (API, Database, Logic). Não sáng sớm rất phù hợp cho logic phức tạp.
    *   Chiều (14h - 18h): Ghép Frontend (UI, CSS, Móc API).
    *   Tối: Tắt máy nghỉ ngơi, hoặc chỉ lướt tìm thư viện hỗ trợ.
3. **Mưu mẹo về UI/UX:** Đừng tự thiết kế nút bấm, bảng biểu. Khách hàng B2B không cần phần mềm "đẹp nghệ thuật", họ cần **rõ ràng và chuyên nghiệp**. Dùng ngay **Ant Design (React)** hoặc **Mantine**. Giao diện mặc định của chúng đã ra dáng Enterprise rồi.
4. **Viết Nhật Ký (Devlog):** Cuối mỗi tuần thứ 6, hãy gửi 1 email cực ngắn cho sếp STAX: *"Báo cáo tuần: Đã hoàn thành 100% API cho Lead. Tuần tới sẽ ghép giao diện. Không có rủi ro gì."* Khách hàng nhận được email này sẽ CỰC KỲ yên tâm và không bao giờ gọi hối thúc bạn.
