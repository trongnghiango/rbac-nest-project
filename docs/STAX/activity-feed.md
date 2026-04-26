# 🗓️ OMNICHANNEL ACTIVITY FEED (DÒNG THỜI GIAN TƯƠNG TÁC HỘI TỤ)

## 1. MỤC TIÊU (OBJECTIVE)
Cung cấp một cái nhìn toàn cảnh (God-view) về toàn bộ lịch sử tương tác của một khách hàng (Organization) trên một giao diện dòng thời gian duy nhất. Giúp nhân viên nắm bắt nhanh bối cảnh mà không cần mở nhiều module khác nhau.

---

## 2. NGUỒN DỮ LIỆU (DATA SOURCES)

Dòng thời gian được hội tụ từ 3 nguồn chính:

| Nguồn | Loại dữ liệu | Ví dụ |
| :--- | :--- | :--- |
| **Audit Logs** | Hệ thống tự động ghi | "Nguyễn Văn A đã chốt Lead", "Hóa đơn FEN-001 đã được thanh toán 5tr". |
| **Interaction Notes** | Nhân viên nhập thủ công | "Đã gọi điện tư vấn, khách báo đang đi công tác hẹn tuần sau". |
| **System Events** | Các thay đổi trạng thái | "Hợp đồng đã tự động kích hoạt", "Nhân viên B được gán quản lý". |

---

## 3. KIẾN TRÚC THỰC THI (ARCHITECTURE)

### A. Tầng Dữ liệu (Database)
1.  **Sử dụng lại `audit_logs`**: Tận dụng hạ tầng đã có ở Phase 1.
2.  **Bổ sung `interaction_notes`**:
    *   `id`: bigserial
    *   `organization_id`: FK -> organizations
    *   `content`: text (Hỗ trợ Markdown cơ bản)
    *   `created_by`: FK -> users
    *   `metadata`: jsonb (Đính kèm file, thẻ tag)

### B. Tầng Nghiệp vụ (Application)
*   **ActivityFeedService**: Chịu trách nhiệm truy vấn (Query) và định dạng (Formatting).
*   **Formatting Engine**: Chuyển đổi dữ liệu JSON thô từ Audit Log thành câu văn xuôi tiếng Việt (VD: {action: 'LEAD.WON'} -> "Đã chốt hợp đồng thành công").

---

## 4. THIẾT KẾ API (API DESIGN)

### `GET /api/v1/organizations/:id/timeline`
*   **Query Params**: `page`, `limit`, `type` (filter theo log hệ thống hoặc note thủ công).
*   **Response Structure**:
```json
{
  "data": [
    {
      "id": "...",
      "timestamp": "2026-04-26T10:00:00Z",
      "type": "SYSTEM_AUDIT | HUMAN_NOTE",
      "actor": { "id": 1, "name": "Trọng Nghĩa" },
      "display_text": "Đã ghi nhận thanh toán 10,000,000 VND cho hóa đơn FEN-20260426",
      "severity": "INFO",
      "reference": { "type": "finotes", "id": "99" }
    }
  ],
  "pagination": { ... }
}
```

---

## 5. LỘ TRÌNH TRIỂN KHAI (IMPLEMENTATION STEPS)

1.  **Bước 1**: Tạo Schema & Module cho `InteractionNote`.
2.  **Bước 2**: Xây dựng `ActivityFeedService` (Logic hội tụ dữ liệu).
3.  **Bước 3**: Cài đặt Formatting Engine để chuyển log sang ngôn ngữ người dùng.
4.  **Bước 4**: Expose API Controller.

---
*Tài liệu được khởi tạo ngày 26/04/2026 bởi Antigravity AI.*
