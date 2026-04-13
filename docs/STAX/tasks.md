# TÀI LIỆU HƯỚNG DẪN TỪ A-Z: QUẢN LÝ DỰ ÁN STAX BẰNG GITHUB PROJECTS

## PHẦN 1: THIẾT LẬP NỀN MÓNG (Tại kho chứa Source Code)

Trước khi tạo Bảng (Board), chúng ta cần thiết lập Nhãn (Labels) và Cột mốc (Milestones) tại kho code (Repository) của bạn.

### Bước 1.1: Tạo Nhãn (Labels) để phân loại
*Việc này giúp bạn nhìn lướt qua là biết task nào làm Backend, task nào làm Frontend.*
1. Truy cập vào Repository chứa source code ERP của bạn.
2. Nhìn lên thanh menu ngang phía trên cùng, bấm vào tab **Issues**.
3. Bấm vào nút **Labels** (nằm cạnh thanh tìm kiếm).
4. Bấm nút xanh **New label** để tạo các nhãn sau (chọn màu cho dễ nhìn):
   * Tên: `backend` | Màu xanh lá | Mô tả: API, Database, Logic.
   * Tên: `frontend` | Màu xanh dương | Mô tả: UI, React, CSS.
   * Tên: `bug` | Màu đỏ | Mô tả: Lỗi cần fix gấp.
   * Tên: `feature` | Màu tím | Mô tả: Tính năng mới.

### Bước 1.2: Tạo Cột mốc (Milestones) theo lộ trình 22 Tuần
*Đây là công cụ chống trễ Deadline cực mạnh.*
1. Vẫn ở tab **Issues**, bấm vào nút **Milestones** (nằm cạnh nút Labels).
2. Bấm nút xanh **New milestone**.
3. Lần lượt tạo các Milestone dựa trên lịch trình ta đã chốt:
   * **Title:** `M1: Core & HRM (Sprint 1-2)` | **Due date:** [Chọn ngày cuối cùng của tuần thứ 4] | Bấm **Create milestone**.
   * **Title:** `M2: CRM & File Storage (Sprint 3-4)` | **Due date:** [Chọn ngày cuối cùng của tuần 8] | Bấm **Create milestone**.
   * **Title:** `M3: Finote & Luồng duyệt (Sprint 5-6)` | **Due date:** [Chọn ngày cuối cùng của tuần 12] | Bấm **Create milestone**.
   * *(Bạn có thể tạo dần các Milestone sau).*

---

## PHẦN 2: TẠO BẢNG ĐIỀU KHIỂN (GITHUB PROJECTS)

Đây sẽ là nơi bạn mở ra mỗi sáng thức dậy.

### Bước 2.1: Tạo Project mới
1. Bấm vào tab **Projects** trên thanh menu ngang của Repository.
2. Bấm nút xanh **Link a project**, chọn **New project** (Nó sẽ mở ra một trang mới).
3. Một bảng chọn hiện ra, bạn chọn **Board** (Biểu tượng các cột giống Trello) -> Bấm **Create**.
4. Ở góc trên cùng bên trái (chỗ có chữ *Untitled project*), click vào và đổi tên thành: **STAX ERP/HRM - Command Center**.

### Bước 2.2: Sắp xếp các Cột (Columns) cho luồng Agile
Mặc định GitHub cho bạn 3 cột: *Todo, In Progress, Done*. Hãy đổi lại cho chuyên nghiệp.
1. Click vào chữ **Todo**, chọn **Rename**, đổi thành: **Backlog (Kho chứa)**.
2. Click vào dấu cộng **`+`** ở cột cuối cùng -> Thêm cột mới, đặt tên là: **Sprint Hiện Tại**.
3. Click vào chữ **In Progress**, đổi tên thành: **Doing (Đang code)**.
4. Click vào dấu cộng **`+`**, thêm cột: **Testing / UAT**.
5. Kéo thả tiêu đề các cột để sắp xếp theo đúng thứ tự từ trái qua phải:
   **`Backlog` ➡️ `Sprint Hiện Tại` ➡️ `Doing` ➡️ `Testing / UAT` ➡️ `Done`**

---

## PHẦN 3: ĐƯA CÔNG VIỆC VÀO HỆ THỐNG (TẠO ISSUES)

Tuyệt đối không tạo Task bằng cách gõ trực tiếp vào bảng Project. **Bắt buộc phải tạo bằng Issues** để gắn với Source code.

### Bước 3.1: Cách tạo 1 Task chuẩn chỉnh
1. Quay lại tab **Issues** của Repository -> Bấm **New Issue**.
2. **Title:** Đặt tên rõ ràng. (VD: `API CRUD Phòng ban (Materialized Path)`).
3. **Write (Nội dung):** Dùng tính năng Check-list của Markdown để chia nhỏ việc. Gõ như sau:
   ```markdown
   - [ ] Viết API Create OrgUnit
   - [ ] Viết API Update & Di chuyển Path
   - [ ] Viết API Lấy danh sách dạng Tree
   - [ ] Viết Unit Test
   ```
4. **Nhìn sang cột menu bên phải màn hình, thiết lập 4 thứ quan trọng nhất:**
   * **Assignees:** Click vào và chọn tên bạn (giao việc cho chính mình).
   * **Labels:** Chọn nhãn `backend` và `feature`.
   * **Projects:** Click vào và chọn bảng **STAX ERP/HRM - Command Center** (vừa tạo ở Phần 2).
   * **Milestone:** Chọn **M1: Core & HRM**.
5. Bấm nút xanh **Submit new issue**. Lập tức Issue này sẽ được gắn mã số (Ví dụ: **#15**).

*(Lặp lại bước này để tạo khoảng 10-15 Issues cho toàn bộ công việc của Sprint 1 & 2).*

---

## PHẦN 4: SETUP "PHÉP THUẬT" TỰ ĐỘNG HÓA (AUTOMATION)

Làm xong bước này, bạn sẽ không cần dùng chuột để kéo thả thẻ nữa.

### Bước 4.1: Tự động đưa Issue vào bảng Project
1. Mở bảng Project **STAX ERP/HRM - Command Center** của bạn lên.
2. Nhìn lên góc trên cùng bên phải, click vào dấu **`...`** -> Chọn **Workflows**.
3. Ở menu bên trái, chọn **Auto-add to project**.
4. Bấm nút **Edit** ở góc phải -> Gõ tên Repository của bạn vào thanh tìm kiếm và chọn nó.
5. Bấm nút xanh **Save and turn on workflow**.
   *(Từ giờ, cứ tạo Issue mới là nó tự động chui vào cột Backlog của bảng).*

---

## PHẦN 5: QUY TRÌNH LÀM VIỆC HẰNG NGÀY CỦA BẠN (WORKFLOW)

Đây là cách bạn vận hành hệ thống này trong suốt 22 tuần để không bao giờ bị trễ deadline hay stress.

### 🌅 Buổi Sáng: Lên kế hoạch (Planning)
1. Mở bảng Project **STAX ERP/HRM** lên.
2. Nếu hôm nay là ngày đầu tuần, hãy nhìn cột **Backlog**. Chọn những task bạn sẽ làm trong tuần này và **kéo thả** chúng sang cột **Sprint Hiện Tại**.
3. Bắt đầu giờ code: Chọn ĐÚNG 1 THẺ từ cột *Sprint Hiện Tại* kéo sang cột **Doing**. 
   *(Tuyệt đối kỷ luật: Cột Doing không được có quá 2 thẻ. Mắt bạn chỉ tập trung vào thẻ đang nằm ở cột Doing).*

### 💻 Quá Trình Code: Nhấn nút "Phép thuật"
1. Bạn mở VSCode, viết code cho Task số **#15** (`API CRUD Phòng ban`).
2. Tích dần vào các ô Check-box bạn đã tạo ở Bước 3.1.
3. Khi code xong hoàn toàn tính năng này, hãy dùng "Câu thần chú" của GitHub.
4. Mở Terminal và gõ chính xác cú pháp commit sau:
   `git commit -m "feat: hoan thanh API phong ban (resolves #15)"`
   *(Từ khóa quan trọng là `resolves #15`, `closes #15` hoặc `fixes #15`).*
5. Gõ lệnh `git push`.

### 🌇 Buổi Chiều/Tối: Tận hưởng thành quả
1. Mở lại bảng Project trên GitHub.
2. Bạn sẽ há hốc mồm khi thấy: Issue **#15** đã tự động chuyển sang màu tím (Closed).
3. Thẻ công việc đó đã **TỰ ĐỘNG BAY TỪ CỘT 'DOING' SANG CỘT 'DONE'**. Bạn không hề đụng 1 ngón tay nào vào chuột!
4. Cảm giác nhìn cột **Done** ngày càng dài ra vào cuối tuần sẽ giúp não bộ bạn tiết ra Dopamine, đập tan mọi sự mệt mỏi và stress.

---

### TỔNG KẾT BÍ KÍP DÀNH CHO SOLO DEV:
*   Đừng bao giờ để mọi thứ trong đầu. Có bug? Tạo Issue. Khách đòi thêm nút? Tạo Issue.
*   Nhờ có **Milestones**, bạn luôn biết mình có đang đi đúng tiến độ của Giai đoạn 1 hay không (Nó có thanh Progress bar xanh lá cây hiển thị % hoàn thành rất đẹp).
*   Nếu khách hàng STAX muốn xem tiến độ, hãy gửi cho họ đường link của bảng Project này (Nhớ set quyền ở mức Read). Họ vào xem sẽ thấy bạn làm việc bài bản như một tập đoàn công nghệ lớn.

Hãy thực hành setup ngay bây giờ với 1 Issue test thử, bạn sẽ ghiền cách làm việc này ngay lập tức! Chúc bạn làm chủ dự án thành công.