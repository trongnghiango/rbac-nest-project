# 🏛️ STAX: Professional Role-Based Interface Blueprint

Chào mừng bạn đến với tài liệu thiết kế tương tác tầng cao. Tài liệu này giúp bạn hình dung cách các nhân viên và sếp tại STAX làm việc hằng ngày thông qua hệ thống Role-Based Access Control (RBAC).

---

## 1. Vai trò & Chân dung người dùng (Personas)

Hệ thống STAX phân cấp dựa trên 3 nhóm vai trò chính:

### 🧑‍💻 Nhóm Nhân viên (STAFF)
- **Tư duy:** Tập trung vào danh sách công việc cá nhân. Cần giao diện tối giản, tập trung vào hành động (Call, Note, Create Lead).
- **Quyền hạn:** Thường chỉ xem dữ liệu trong phạm vi được gán (`Owner Only`).
- **Nhu cầu:** Dashboard hiển thị: Leads hôm nay cần gọi, Finotes đang nợ của khách hàng mình phụ trách.

### 🧑‍💼 Nhóm Lãnh đạo (MANAGER / LEADER)
- **Tư duy:** Quản trị hiệu suất đội ngũ. Cần cái nhìn tổng quan (Aggregated Views).
- **Quyền hạn:** Xem được dữ liệu của toàn bộ đơn vị (`OrgUnit Scope`).
- **Nhu cầu:** Dashboard hiển thị: Tỷ lệ chốt của team, Tổng nợ Finote theo phòng ban, Review các hành động nhạy cảm.

### 🛡️ Nhóm Quản trị (ADMIN / SUPER_ADMIN)
- **Tư duy:** Bảo trì hệ thống và cấu hình.
- **Quyền hạn:** Toàn quyền (`*`).
- **Nhu cầu:** Dashboard hiển thị: Audit logs, Cấu hình RBAC, Quản lý tài khoản.

---

## 2. Ma trận Tương tác Nhân viên ↔ Sếp (Daily Workflows)

Đây là chi tiết cách hai bên tương tác trên UI:

### Luồng 1: Review & Phê duyệt (Approval Flow)
1.  **Nhân viên:** Tạo một `Finote` chi tiền (Expense). Tránh thái ban đầu là `PENDING`.
2.  **Hệ thống:** Bắn thông báo cho Sếp.
3.  **Sếp:** Vào màn hình "Phê duyệt tài chính". 
    - UI của Sếp sẽ hiện thêm nút `[APPROVE]` và `[REJECT]`.
    - Backend trả về `_actions.canApprove: true` cho Sếp nhưng `false` cho Nhân viên.
4.  **Hành động:** Sếp nhấn Approve ➡️ Trạng thái chuyển thành `APPROVED`.

### Luồng 2: Điều phối & Giao việc (Assignment Flow)
1.  **Sếp:** Xem danh sách `Leads` mới từ nguồn Marketing.
2.  **Hành động:** Sếp chọn Lead và chọn "Giao cho nhân viên". 
    - API: `PATCH /crm/leads/:id/assign`.
3.  **Nhân viên:** Nhận được thông báo "Bạn được gán Lead mới". Lead này xuất hiện trong Dashboard "My Work" của nhân viên.

---

## 3. Bản đồ API cho Frontend (UI Implementation Map)

Dưới đây là các đầu API bạn cần kết nối tương ứng với vai trò:

| Tính năng | API tiêu chuẩn | Quyền yêu cầu (Permission) | UI Component Gợi ý |
| :--- | :--- | :--- | :--- |
| **Dashboard cá nhân** | `GET /system/bootstrap` | `user:read` | Profile Card, To-do list |
| **Xem danh sách Lead** | `GET /crm/leads` | `crm.lead:read` | Table với tính năng lọc theo PIC |
| **Phê duyệt tiền** | `POST /accounting/finotes/:id/approve` | `finote:approve` | Nút "Duyệt" (chỉ hiện cho Sếp) |
| **Gán quyền (RBAC)** | `POST /rbac/assign` | `rbac:manage` | Modal danh sách Role & Permission |

---

## 4. Bổ sung API Gợi ý (Proposed Enhancements)

Để chuyên nghiệp hơn, tôi đề xuất bổ sung các API sau phục vụ tương tác:

1.  **`GET /system/my-team/summary`**: Dành cho Sếp xem nhanh các chỉ số của nhân viên cấp dưới (Số lead đang xử lý, doanh số trong tháng).
2.  **`POST /system/mentions`**: Cho phép Nhân viên tag Sếp vào một Ghi chú (Note) để xin ý kiến chỉ đạo.
3.  **`GET /system/notifications/ws`**: Ký kênh Websocket để nhận thông báo real-time khi có phê duyệt hoặc gán việc.

---

## 5. Lưu ý cho việc dựng UI cá nhân hóa

- **Cấp bậc (Hierarchy):** Khi Sếp xem profile của Nhân viên, UI nên hiển thị các nút quản trị. Khi xem profile của Sếp cấp trên, các nút đó phải ẩn đi.
- **Data Scoping:** Frontend không cần lo lắng về việc lọc dữ liệu. Backend đã tự động lọc theo `organization_id` và `org_unit_id` dựa trên Role của bạn. Bạn chỉ cần gọi đúng Endpoint.

---
*Tài liệu này được thiết kế để bạn có thể bắt đầu dựng Prototype hoàn chỉnh cho luồng tương tác Sếp-Nhân viên.*
