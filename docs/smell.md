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



# Kế hoạch Tái cấu trúc: Audit Log & Chuẩn hóa Database Schema

Tài liệu này đưa ra phương án giải quyết 2 code smell nghiêm trọng đã phân tích ở trên, đảm bảo hệ thống STAX hoạt động ổn định và chính xác dưới tải cao.

## 1. Tóm tắt vấn đề

- **Audit Log Sync-Blocking:** Các tác vụ quan trọng như chốt hợp đồng và tạo dòng tiền đang gọi trực tiếp lệnh Insert vào DB để ghi log. Nếu tiến trình ghi log bị lỗi (VD: cấu trúc sai, DB timeout), toàn bộ transaction tài chính sẽ bị huỷ bỏ, đi ngược với ADR 005 (Fire-and-forget). Hơn nữa, việc gọi không có hàm catch sẽ dẫn đến UnhandledPromiseRejection.
- **Lỏng lẻo Schema (Schema Definitions Mismatch):** Các bảng `contracts` và `leads` định nghĩa quá nhiều trạng thái Enum thừa so với triết lý thiết kế (Process vs Entity).

## 2. Proposed Changes (Thay đổi đề xuất)

### Core Shared (Tier 1 Foundation)

Thay đổi định dạng hàm của Port để không trả về Promise, ép buộc Client phải gọi theo giao thức đồng bộ/fire-and-forget chuẩn xác. Thay vì client tự await (và tự gánh lỗi), tầng Logging sẽ nuốt lỗi.

#### [MODIFY] [audit-log.port.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/core/shared/application/ports/audit-log.port.ts)
- Thay đổi chữ ký Interface `log(entry: AuditLogEntry): Promise<void>;` thành `log(entry: AuditLogEntry): void;`.

### Logging Module (Thiết kế lại cơ chế Fire-and-forget)

Thay đổi Service hiện tại để đẩy lệnh lưu DB vào nền (Background Task / Detached Context).

#### [MODIFY] [drizzle-audit-log.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/logging/infrastructure/persistence/drizzle-audit-log.service.ts)
- Gỡ bỏ `async` khỏi hàm `log()`. 
- Đưa thao tác `db.insert(...)` vào bên trong một hàm async chạy ngầm (Ví dụ: `setImmediate()` hoặc bắt Promise `.catch()`).
- Thêm cơ chế bắt lỗi để in ra Winston Logger (Console/File) nếu ghi DB thất bại, nhưng đảm bảo không ném ngược lỗi (throw) ra ngoài. Mẫu code:
```typescript
    log(entry: AuditLogEntry): void {
        const db = this.getDb();
        setImmediate(async () => {
            try {
                await db.insert(schema.auditLogs).values({...});
            } catch (error) {
                console.error('[AuditLog FireAndForget Error]:', error);
            }
        });
    }
```

### CRM Database Schemas (Đồng bộ ngôn ngữ Ubiquitous Language)

Sửa đổi định nghĩa Drizzle Enums phục vụ cho việc Push lên Database.

#### [MODIFY] [contracts.schema.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/database/schema/crm/contracts.schema.ts)
- Update `contractStatusEnum` để chỉ chứa các loại hình cốt lõi theo `architecture.md`: `['SIGNED', 'LIQUIDATED']`.

#### [MODIFY] [leads.schema.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/database/schema/crm/leads.schema.ts)
- Update đổi tên `status` thành `stage` theo đúng Document.
- Rút gọn Lead Stage Enum: `['CONSULTING', 'WON', 'FAILED']`.

---

## 3. Open Questions (Câu hỏi cần đánh giá)

> [!WARNING]
> **Về việc thu hẹp Database Enums:** Việc thu hẹp Enum của `contracts` (Xóa DRAFT, EXPIRED...) và `leads` sẽ gây lỗi (Data conflict) nếu Database của dự án đã có dữ liệu mẫu chứa các Enum hiện tại, hoặc quá trình Migration (363 Finotes, 1172 Leads) đã nhét dữ liệu ngoài luồng vào.
> **Quyết định:** Bạn muốn tôi (A) Cứ ép lại Enum schema theo đúng `architecture.md` hay (B) Cập nhật lại tài liệu `architecture.md` để thừa nhận sự tồn tại của các Enum bổ sung (như DRAFT, EXPIRED)?

> [!TIP]
> **Về cơ sở hạ tầng nền:** Phương pháp `setImmediate` dùng I/O queue của Node.js giải quyết triệt để lỗi blocking và unhandled rejections nhanh chóng mà không cần cài thêm thư viện (như RabbitMQ hay @nestjs/event-emitter). Nếu STAX mở rộng, sau này có thể nâng cấp file service này để đẩy ra message broker.

## 4. Verification Plan

### Manual Verification
1. Sau khi chỉnh sửa, ta sẽ gõ thử một lệnh (viết Test Script) gọi Service `PaymentReconciliationService` để kiểm tra. Giao dịch sẽ phải báo thực hiện thành công Transaction nhanh chóng, và sau đó ở nền Database có record Audit mới.
2. Sẽ chèn thử code phá lỗi (ví dụ Insert một resourceId bị sai kiểu hoặc chèn dữ liệu quá giới hạn cột) vào lớp `DrizzleAuditLogService`. Transaction thanh toán vẫn phải hoàn tất mà không bị throw ra màn hình hay crash process Node.js.
