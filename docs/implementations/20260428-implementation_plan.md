# Kế Hoạch Rà Soát & Củng Cố Kiến Trúc Hệ Thống STAX

Kế hoạch này phác thảo các công việc cần thiết sau khi rà soát thư mục `src/` để đảm bảo tuân thủ nghiêm ngặt "Hiến pháp hệ thống" (Clean Architecture, Clean Code, Fire-and-forget Logging, Unit Test cho Core Modules) cũng như cập nhật lại ngữ cảnh tài liệu hệ thống.

## User Review Required

> [!WARNING]  
> Các thay đổi này liên quan trực tiếp đến Core Domain (Kế toán, Phân quyền) và Presentation Layer của tổ chức. Vui lòng xác nhận sự đồng ý của bạn với các điểm Fix Code Smell dưới đây.

## Proposed Changes

### Thay đổi Tài liệu (Documentation)

#### [MODIFY] [README.md](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/docs/STAX/context/README.md)
- Cập nhật lại ngày `Cập nhật gần nhất` thành thời điểm hiện tại `28/04/2026`.
- Chỉnh sửa nội dung phản ánh đợt rà soát Code Smell và tuân thủ Clean Architecture.

---

### Khắc Phục Audit Log & Logging Patterns

Tuân thủ **ADR 005: Fire-and-forget Logging Pattern** quy định rằng việc ghi log không được làm lỗi nghiệp vụ chính (phải bao bọc bằng `try-catch`). 

#### [MODIFY] [payment-reconciliation.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/accounting/application/services/payment-reconciliation.service.ts)
- Bọc khối lệnh calls `this.auditLog.log` bên trong một khối `try {} catch(e) {}` (Fire-and-forget) sao cho nếu database log bị kẹt / lỗi thì tiến trình thanh toán (transaction) vẫn thành công.

#### [MODIFY] [rbac-manage.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/rbac/application/services/rbac-manage.service.ts)
- Bọc lệnh gọi `this.auditLog.log` bên trong khối `try/catch`. 

#### [MODIFY] [user-account.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/user/application/services/user-account.service.ts)
- Bọc lệnh gọi `this.auditLog.log` bên trong khối `try/catch`.

#### [MODIFY] [lead-workflow.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/crm/application/services/lead-workflow.service.ts)
- Loại bỏ injection của `AUDIT_LOG_PORT` thừa thãi (do tiến trình hiện tại sử dụng Domain Events `EventBus` thay vì ghi auditLog trực tiếp).

---

### Khắc Phục Lỗi Ánh Xạ Thực Thể (Entity Leaking)

Tuân thủ **Triết lý #6: Security by Design**: Tuyệt đối không gửi Entity thô về Client.

#### [MODIFY] [org-structure.controller.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/org-structure/infrastructure/controllers/org-structure.controller.ts)
- Bổ sung logic `DTO Mapper` hoặc làm sạch dữ liệu trong Controller (chống trả ngược Entity thô của Drizzle ORM chưa qua map sang chuẩn ResponseDTO). Sẽ sử dụng `OrgUnitResponseDto` nếu có, nếu chưa sẽ ánh xạ sang định dạng trả về an toàn.

---

### Bổ Sung Unit Test Cho Core Fortress

Tuân thủ **Triết lý #5: Tư duy Pháo đài (Fortress Mindset)** yêu cầu mọi ngõ ngách Lõi / Phân quyền phải có Unit Test. Hiện tại thư mục code chưa có test spec cho một vài core services. 

#### [NEW] [rbac-manager.service.spec.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/rbac/application/services/rbac-manager.service.spec.ts)
- Tạo kịch bản Unit Test trống (scaffolding) kiểm thử khả năng gán Role.

#### [NEW] [role.service.spec.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/rbac/application/services/role.service.spec.ts)
- Tạo kịch bản Unit Test trống cho Role Management.

#### [NEW] [finote.service.spec.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/accounting/application/services/finote.service.spec.ts)
- Tạo kịch bản Unit Test xác nhận phát hành `FinoteCreatedEvent` dòng tiền.

## Open Questions
- Với phần `DTO Mapper` trong `OrgStructureController`, anh có muốn em tự động định nghĩa class `OrgUnitResponseDto.ts` hay chỉ cần map thuần túy gỡ bỏ các trường ORM thừa thãi là được?

## Verification Plan
1. **Automated Tests:** Chạy `npm run test` để đảm bảo hệ thống không bị phá vỡ sau khi wrap try-catch và xóa bỏ thư viện thừa.
2. **Build Test:** Bật lệnh `npx tsc --noEmit` để đảm bảo hệ thống không xuất hiện bất kỳ lỗi TypeScript nào.
3. Chạy lệnh `npm run test` trên các spec files vừa tạo để đảm bảo test coverage đạt chuẩn.
