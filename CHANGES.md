# 📝 NHẬT KÝ THAY ĐỔI & REFACTOR (CHANGES.MD)

File này ghi lại các quyết định quan trọng về kiến trúc và các đợt Refactor mã nguồn để đảm bảo hệ thống tuân thủ "Hiến pháp" backend.

## [2026-04-24] - Refactor Cơ chế Giao tiếp Cross-Module (Smell #6)

### 🚀 Thay đổi chính
1.  **Cập nhật BACKEND_CONTEXT.md:** Định nghĩa rõ ràng cơ chế **SYNC (Orchestration)** và **ASYNC (Choreography)**.
2.  **Xây dựng Domain Ports:** Tạo ra các Interface Service (`IUserAccountService`, `IRbacManageService`) tại tầng Domain của Module đích.
3.  **Refactor `CompanyImportService`:** Chuyển từ việc truy cập Repository trực tiếp sang gọi thông qua các Port Service.

---

### 🔍 Chi tiết kỹ thuật & Pattern áp dụng

#### 1. Pattern: Inter-Module Domain Service Port (Sync Orchestration)
Khi Module A (ví dụ: `OrgStructure`) cần thực hiện một luồng nghiệp vụ phức tạp liên quan đến Module B (ví dụ: `User`), thay vì Module A "thọc tay" vào Database của Module B, nó sẽ gọi qua một "Cổng" (Port) được Module B cung cấp.

*   **So sánh với cách cũ (Direct Repository):**
    *   **Cách cũ:** `OrgStructure` Inject `UserRepository`. 
        *   *Hệ quả:* Module Org biết quá nhiều về cấu trúc bảng của User. Nếu DB của User đổi từ SQL sang MongoDB, module Org bị vỡ.
    *   **Cách mới:** `OrgStructure` Inject `IUserAccountService`.
        *   *Lợi ích:* Module Org chỉ cần biết "Tôi muốn tạo tài khoản cho nhân viên này". Việc tạo như thế nào, lưu vào đâu là việc của Module User. Đây là tính **Encapsulation (Đóng gói)** tuyệt đối.

#### 2. Phân loại Task: Sync vs Async
Chúng ta đã giải quyết bài toán "Làm sao biết Task thành công nếu dùng Event?" bằng cách phân loại:

*   **SYNC (Trọng yếu):** Dùng cho việc tạo User trong lúc Import. 
    *   *Tại sao:* Vì chúng ta cần lấy `userId` ngay lập tức để gán Role ở dòng code tiếp theo. Việc này được thực hiện đồng bộ và chạy chung **Atomic Transaction (ALS)**. Nếu tạo User thất bại, toàn bộ quá trình Import OrgUnit sẽ Rollback tự động.
*   **ASYNC (Phụ trợ):** Dùng cho việc bắn Event `CoreEmployeeImported`.
    *   *Tại sao:* Việc khởi tạo hồ sơ nhân sự chi tiết có thể để các Listener xử lý sau, không cần chặn luồng Import chính.

---

### 💡 Tại sao cách này tối ưu nhất?

1.  **Bảo vệ toàn vẹn dữ liệu:** Nhờ sử dụng **ALS (Async Local Storage)**, dù gọi xuyên Module qua Port Service, tất cả vẫn nằm trong cùng một Transaction ID. Nếu một khâu lỗi, tất cả sẽ Rollback.
2.  **Tránh Circular Dependency:** Việc giao tiếp qua Interface giúp NestJS giải quyết các lỗi tham chiếu vòng một cách dễ dàng hơn nhiều so với việc Inject trực tiếp các Class Implementation.
3.  **Dễ Unit Test:** Bạn có thể dễ dàng Mock `IUserAccountService` khi viết test cho `CompanyImportService` mà không cần quan tâm đến logic phức tạp của module User.

---

### ✅ Trạng thái Smell #6: ĐÃ XỬ LÝ (RESOLVED)
*   Tầng Application không còn rò rỉ việc truy cập Repository của module khác.
*   Cơ chế giao tiếp đồng bộ đã có "hợp đồng" (Interface) rõ ràng.
