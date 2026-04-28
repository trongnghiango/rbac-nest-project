# Kế hoạch Bổ sung API Phục vụ UI/UX Enterprise

Giai đoạn này nhắm tới việc tích hợp các Backend API làm nền móng để xây dựng một Frontend (React/Vue/Angular) Mượt mà, linh hoạt và xịn xò chuẩn ERP.

## Trạng thái Yêu cầu Duyệt

> [!IMPORTANT]  
> Xin ý kiến xác nhận của anh để chốt thiết kế:
>
> 1. Tính cấp thiết: Ở đợt *Sprint* đầu tiên, anh muốn dồn nguồn lực để hoàn tất toàn bộ **Cơ chế Phân trang & Filter chung** cho các Table (bài toán cơ bản nhất), hay anh muốn cắm **OmniSearch** (Tìm kiếm đa vũ trụ) lên ngay?
> 2. Anh có đồng thuận với 3 file tài liệu mới vừa chốt (Kế hoạch này + File `ui-integration.md` + file `api-documentation.md`) không? Nếu có, em có thể bắt đầu tự code tính năng được giao.

## Kế hoạch Cụ thể

### Hạng mục 1: Xây dựng Cơ chế DTO Phân trang (Pagination) chung
- **Vấn đề Backend:** Các API Get list như `/accounting/finotes`, `/crm/leads` chỉ trả về mảng dữ liệu.
- **Giải pháp:**
  - Thiết kế thư mục: `src/core/shared/application/pagination/`.
  - Thiết lập `PaginationRequestDto` (chứa `page`, `limit`, `sortBy`, `search`).
  - Thiết lập `PaginationResponseDto` (chứa array dữ liệu mảng và `meta` info).
  - Viết util helper `queryBuilder` cho **Drizzle ORM** để tự dịch các DTO kia thành các hàm query limit, offset ở tầng Hạ tầng (Repository).

### Hạng mục 2: Xây dựng API Khởi tạo App
- **Vấn đề:** Frontend mới login luôn chịu gánh nặng đi gom profile, role, notifications ở 3 chốt chặn.
- **Giải pháp:**
  - Xây dựng: `GET /system/bootstrap`.
  - Nó gọi 3 tầng Use Cases của UserService, RbacManagerService để trả về một JSON cục u duy nhất cho cục Frontend Redux Store nuốt thẳng vào.

### Hạng mục 3: Xây dựng API Master Data (Lookup / Enums)
- **Giải pháp:**
  - Xây thêm Endpoint tại Shared Module hoặc System Module: `GET /system/lookups` 
  - Khai báo list cấu hình tĩnh (ví dụ `LeadStage`, `ContractStatus`) cho phép frontend biến hoàn toàn Label hiển thị thành dạng động.

## Kế hoạch Xác nhận & Chạy thử
- Sẽ chạy Unit Tests cho bộ helper Drizzle Pagination vì bộ này sẽ áp dụng mọi ngóc ngách của Data Grid.
- Dùng `curl` (hoặc test) để thử Pagination và Lookup ngay tại Server cục bộ.
