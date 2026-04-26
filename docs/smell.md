Dựa trên các quy định kiến trúc trong thư mục `docs/STAX/context/` (cụ thể là `architecture.md`, `philosophy.md` và `strategy.md`), tôi đã rà soát mã nguồn trong thư mục `src/` và phát hiện một số **Code Smell** và **Vi phạm Nguyên tắc Kiến trúc** như sau:

### 1. Vi phạm nghiêm trọng: Cơ chế Fire-and-forget của Audit Log (ADR 005)
Theo bảng ADR 005 trong `architecture.md` quy định: 
> "Việc ghi log không được phép làm lỗi luồng nghiệp vụ chính. Phải sử dụng `try-catch` bao bọc lệnh ghi log. Nếu DB ghi log bị lỗi... hệ thống vẫn phải cho phép hoàn tất giao dịch."

**Thực trạng trong `src/`:**
Tại nhiều Domain Service cốt lõi, thao tác `this.auditLog.log(...)` đang được gọi trực tiếp và thả nổi mà **không hề được bọc trong `try...catch`**. Nếu tiến trình ghi Log bị lỗi (ví dụ rớt mạng, mất kết nối RabbitMQ, timeout DB), toàn bộ Transaction nghiệp vụ chính sẽ bị roll-back.
*   **Các file vi phạm:**
    *   `src/modules/crm/application/services/lead-workflow.service.ts` tại dòng 91.
    *   `src/modules/accounting/application/services/payment-reconciliation.service.ts` tại dòng 81.
    *   `src/modules/rbac/application/services/rbac-manage.service.ts` tại dòng 31.
    *   `src/modules/user/application/services/user-account.service.ts` tại dòng 40.

### 2. Vi phạm Ngôn ngữ Nghiệp vụ (Ubiquitous Language) tại Schema Database
Sự thiếu đồng bộ giữa mô hình lõi được thống nhất với Business (trong `architecture.md`) và Drizzle Schema thực tế.

*   **Về `CONTRACTS` (Hợp đồng):**
    *   *Quy định (`architecture.md`)*: Trạng thái hợp đồng chỉ có: `SIGNED` (Đã ký), `LIQUIDATED` (Thanh lý).
    *   *Thực trạng (`src/database/schema/crm/contracts.schema.ts`)*: Định nghĩa Enum `contract_status` sinh ra rất nhiều trạng thái rác là `['DRAFT', 'PENDING', 'ACTIVE', 'EXPIRED', 'TERMINATED']`.
*   **Về `LEADS` (Tiến trình tư vấn khách):**
    *   *Quy định (`architecture.md`)*: Lead chỉ có thuộc tính `stage` bao gồm `CONSULTING | WON | FAILED`.
    *   *Thực trạng (`src/database/schema/crm/leads.schema.ts`)*: Dùng từ khóa là `status` (thay vì `stage`) và định nghĩa hàng loạt trạng thái sale funnel thuần tuý như `NEW, CONTACTED, QUALIFIED, PROPOSAL, NEGOTIATION, WON, LOST, ARCHIVED`.
    > *Smell:* Việc này đi ngược với triết lý "Strict Enum Hardening" và phân biệt rạch ròi giữa "Thực thể" vs "Tiến trình" đã ghi ở tài liệu. Quá nhiều trạng thái mập mờ sẽ làm bể báo cáo hoặc làm phức tạp hóa State Machine.

### 3. Về cấu trúc và bao đóng (Encapsulation)
*   **Hard-coded Strings vs Enums trong Service:** Trong `lead-workflow.service.ts`, có sử dụng chuỗi literal `before: { stage: 'INTERACTIVE' }` để audit log, thay vì map với Enum gốc từ domain. Điều này dễ dẫn tới lỏng lẻo chuẩn hóa dữ liệu khi hệ thống scale lên.

### Đề xuất xử lý
1. **Quick Fix:** Viết một Helper Component hoặc Decorator `withAuditLogTryCatch` để bọc lại toàn bộ lệnh gọi tới Port `IAuditLogService` một cách tự động, thay vì phải kiểm tra thủ công.
2. **Review lại Enums:** Team Dev cần ngồi lại cùng Biz để thống nhất lại xem Drizzle Schema giữ nguyên hay Diagram ở tài liệu cần update lại cho đúng nhịp (tránh tình trạng Dev tự chế state cho các object nghiệp vụ).

Bạn có muốn tôi tự động tạo Refactoring Plan hay tạo file Walkthrough / Artifact để sửa các code smell này ngay bây giờ không?
