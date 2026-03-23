### BỨC TRANH TOÀN CẢNH VỀ CẤP BẬC VAI TRÒ (ROLE HIERARCHY)

Để bạn có cái nhìn rõ ràng nhất về cách hệ thống của bạn (từ file `core_employee.csv` đến `rbac_roles.csv`) đang phối hợp với nhau như thế nào, hãy xem ma trận dưới đây. 

Trong hệ thống RBAC của bạn, quyền lực chảy từ trên xuống dưới theo **Trọng số (Rank)**:

| Cấp bậc (Rank) | Vai trò (Role) | Đối tượng đảm nhiệm | Khả năng (Quyền hạn bao trùm) | Giới hạn (Không được làm gì?) |
| :--- | :--- | :--- | :--- | :--- |
| **Rank 100** *(Vua)* | `SUPER_ADMIN` | CEO, Chủ tịch HĐTV (`ceo_bod`) | **Có mã gen Bypass:** Không cần kiểm tra DB. Đi xuyên qua mọi Guard `@Permissions`. | Không có giới hạn. |
| **Rank 90** *(Tể Tướng)* | `ADMIN` | Giám đốc, GĐ Chi nhánh (`dir_bod`) | Có quyền `manage` trên các module lõi (Quản lý User, Sơ đồ tổ chức, Hồ sơ nhân sự, Báo cáo toàn công ty). | Bị tước quyền `rbac:manage`. Không thể tự phong quyền cho mình hay tước quyền người khác. Phải nhờ IT. |
| **Rank 80** *(Quan Huyện)* | `MANAGER` | Trưởng phòng, Phó phòng (`tp_dv`) | Được giao quyền Quản lý (`manage`) nhưng bị "Scoping" (giới hạn) trong phạm vi Phòng Ban của mình. VD: Chỉ xem/sửa hồ sơ của lính mình. | Không được xóa dữ liệu (Delete). Không được xem dữ liệu của phòng ban khác (Trừ khi được cấp thêm Role chéo). |
| **Rank 70** *(Dân thường)* | `STAFF` | Chuyên viên, Trợ lý, Thực tập sinh | Chỉ có quyền Tạo mới (`create`) và Xem/Sửa (`read/update`) dữ liệu *do chính mình tạo ra*. Xem danh bạ công ty. | Không thể can thiệp vào dữ liệu của đồng nghiệp. Không có quyền `manage`. |
| **Rank 60** *(Khách)* | `USER` | Tài khoản vừa đăng ký mới | Role mặc định khi ai đó tự Register. | Chưa được gán vào sơ đồ tổ chức nên gần như không làm được gì ngoài việc sửa Profile cá nhân. |

### 🧩 Phụ lục: Các Vai Trò Chức Năng (Functional Roles - Add-ons)

Kiến trúc của bạn cho phép 1 User có nhiều Role (Mảng `roles: []`). Nhờ vậy, ta đẻ ra các "Role Chức Năng" để đắp thêm vào cho nhân sự khi cần:

1. **`IT_ADMIN` (Cấp cho `dev_it`):**
   * Mặc dù IT chỉ là chức danh chuyên viên (Rank 70), nhưng được đắp thêm Role này để giữ quyền `rbac:manage` (Làm nhiệm vụ Import file `rbac.csv`) và `user:manage` (Reset pass cho sếp).
2. **`QA_AUDITOR` (Cấp cho `qa_ht`):**
   * Phòng ban kiểm soát chất lượng cần đọc Log hệ thống. Đắp thêm Role này để lấy quyền `audit:view` mà không cần thăng chức họ lên ADMIN.

> **Tóm lại:** Nhờ chia Role theo cấp bậc và đắp thêm Role chức năng, hệ thống của bạn hoàn toàn đáp ứng được bất kỳ sơ đồ tổ chức phức tạp nào ở Hình 1, 2, 3 mà không cần viết thêm 1 dòng code IF/ELSE nào trong Controller!