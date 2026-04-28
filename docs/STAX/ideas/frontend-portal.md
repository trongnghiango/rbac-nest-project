# 🎨 STAX: Frontend Development Portal (FDP)

Chào mừng các Frontend Developer! Tài liệu này được thiết kế để bạn có thể xây dựng UI/UX đẳng cấp cho STAX mà không cần phải "soi" code Backend hay chờ đợi API hoàn thiện.

---

## 🏗️ 1. Nguyên tắc tích hợp (Integration Principles)

Hệ thống STAX sử dụng mô hình **Single Source of Truth** từ Backend.
*   **API Base:** `http://localhost:8080/api`
*   **Auth:** Sử dụng Bearer Token trong Header.
*   **Format:** Luôn là JSON, định dạng `snake_case` cho DB và `camelCase` cho API payload.

---

## 🔄 2. Luồng công việc (Core Workflows)

Dưới đây là sơ đồ giúp bạn hình dung cách các màn hình tương tác với nhau:

### A. Luồng CRM (Leads ➡️ Client)
1.  **Màn danh sách Lead:** Gọi `GET /crm/leads` với phân trang.
2.  **Màn chi tiết:** Hiển thị `Activity Log` (Dòng thời gian tương tác).
3.  **Hành động "Chốt":** Gửi `POST /crm/leads/:id/won`. 
    *   *Kết quả:* Hệ thống tự động redirect sang màn hình Hợp đồng mới.

### B. Luồng Tài chính (Finote ➡️ Payment)
1.  **Tạo phiếu thu:** `POST /accounting/finotes`.
2.  **Gạch nợ:** Chọn bản ghi trong `GET /accounting/cash-transactions` rồi map vào `Finote`.

---

## 🔌 3. Hướng dẫn sử dụng API (Core API Guide)

### 3.1. API Khởi tạo (`/system/bootstrap`)
Đây là API quan trọng nhất. Bạn gọi **1 lần duy nhất** ngay sau khi login.
*   **Dữ liệu thực thể:** Trả về thông tin User hiện tại.
*   **UI Flags:** Chứa các biến boolean (`canManageLeads`, `canApprove`...) để bạn toggle các nút bấm trên UI.

### 3.2. Tra cứu danh mục (`/system/lookups`)
Frontend **không được phép** hardcode các giá trị Enum (ví dụ: trạng thái Lead).
*   Hãy gọi API này để lấy list `label` và `value` cho các Dropdown/Select.

### 3.3. Phân trang chuẩn (Pagination)
Mọi API danh sách đều trả về cấu trúc:
```json
{
  "items": [...],
  "meta": {
    "totalCount": 100,
    "totalPages": 10,
    "currentPage": 1
  }
}
```

---

## 💎 4. Măng Non UI/UX (Pro-tips)

### Xử lý số tiền (Currency)
Nghiêm cấm tính toán số tiền ở Frontend nếu không cần thiết.
*   Giá trị trả về từ Backend luôn là một Object Money: `{ amount: 1000000, currency: "VND" }`.
*   Hãy dùng một Helper function để format hiển thị (ví dụ: `1.000.000đ`).

### Xử lý Trình trạng Actionable
Hãy luôn kiểm tra field `_actions` (nếu có) trong object để disable nút bấm thay vì check `status`. 
*(Xem chi tiết tại [UI-UX Renaissance](../context/ui_ux_renaissance.md))*

---

## 🛠️ 5. Thư mục tài liệu chi tiết (Directory Map)

1.  **[API Schema (Swagger)](http://localhost:8080/api/docs):** Tài liệu kỹ thuật chi tiết nhất từng endpoint.
2.  **[UI Integration Guidelines](./ui_integration.md):** Quy chuẩn render Grid, Table và Form.
3.  **[Business Philosophy](../context/philosophy.md):** Hiểu về "Tại sao" chúng ta thiết kế như vậy.

---
*Cập nhật lần cuối: 28/04/2026 bởi Antigravity AI.*
