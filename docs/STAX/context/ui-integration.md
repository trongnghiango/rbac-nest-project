# Tiêu chuẩn API Tương tác Giao diện (UI/UX API Integration)

## 1. Tầm quan trọng
Để xây dựng một trải nghiệm người dùng (UX) đẳng cấp Enterprise, Backend không thể chỉ trả về raw data từ cơ sở dữ liệu. Backend cần đóng vai trò "dọn sẵn cỗ" để Frontend (React, Vue, Tái cấu trúc Dashboard) có thể render ngay lập tức mà không phải tốn tài nguyên thiết bị tính toán lại.

Tài liệu này xác định các tiêu chuẩn kỹ thuật bắt buộc để Backend bơm dữ liệu cho Frontend một cách tối ưu nhất.

## 2. Nhóm API Bắt Buộc Cần Mở Rộng

### 2.1. Phân trang & Lọc Toàn cục (Global Pagination & Filters)
Nguyên tắc: Bất cứ API `GET` danh sách nào (Leads, Contracts, Users, Finotes) cũng phải được thiết kế dạng Lưới (Grid/Table ready).
- **Yêu cầu Tham số (Query):** `page`, `limit`, `sortBy`, `sortParam`, `search`, `filter[field]`.
- **Yêu cầu Trả về (Response):**
  - Data payload luôn nằm ở thuộc tính `items` hoặc `data`.
  - Phải đi kèm metadata phân trang:
    ```json
    "meta": { "totalCount": 100, "totalPages": 10, "currentPage": 1, "itemsPerPage": 10 }
    ```

### 2.2. Khởi tạo App / Context Bootstrap
- Cung cấp Endpoint `/system/bootstrap` hoặc `/auth/me/context`.
- Endpoint chỉ nên gọi 1 lần duy nhất lúc tải xong màn hình.
- Chứa thông tin tổng hợp:
  - Thông tin thiết lập hệ thống (thời gian, config local).
  - RBAC Flags dành cho UI (Các boolean xác định User được quyền thấy nút gì).
  - Trạng thái chưa đọc thông báo (Notification badges count).

### 2.3. Master Data (Dữ liệu tra cứu Enum)
- Frontend không được phép hardcode các trạng thái (ví dụ Enum Lẽ thường như `FinoteType: [INCOME, EXPENSE]`).
- Đặt tại `/system/lookups` để trả danh mục trạng thái từ Backend về. Nhờ vậy nếu có thêm Type mới, Frontend tự bung mà không rớt build.

### 2.4. Global Omni-Search (Tìm kiếm đa vũ trụ)
- Endpoint `/search/omni` cho phép search 1 string text across rất nhiều Table Khác nhau (Leads, Deals, Organization).
- Trả về tập danh sách đã nhúng phân trang nhưng được chẻ theo Category để gán vào ô Auto-complete của tính năng thanh Search Command.

## 3. Lộ trình Triển khai Code
Căn cứ trên các tiêu chuẩn trên, lộ trình bổ sung các tiện ích API này sẽ được chia làm 3 Phases nhỏ trong Kế hoạch của đợt Phát triển Frontend API Integration.
