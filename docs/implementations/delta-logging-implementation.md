# Tài liệu triển khai: Delta Logging (Diff Optimization)

**Ngày triển khai:** 26/04/2026
**Trạng thái:** Hoàn thành (100%)

## 1. Vấn đề (Context)
Trước khi triển khai Delta Logging, hệ thống thực hiện chụp ảnh toàn bộ trạng thái (Full Snapshot) của các Entity tại mỗi hành động ghi log. Việc này gây ra:
- **Tốn dung lượng Database:** Đặc biệt với các Entity lớn như `Lead` hay `Organization`.
- **Khó khăn khi đối soát:** Người dùng phải tự so sánh 2 khối JSON khổng lồ để tìm ra thay đổi.

## 2. Giải pháp kỹ thuật (Solution)

### A. Core Utility: `ObjectDiff`
Chúng ta xây dựng module `ObjectDiff` tại `src/core/shared/utils/object-diff.util.ts`. Module này có khả năng:
- So sánh sâu (Deep equality check).
- Trích xuất ra các trường bị thay đổi.
- **Exclusion List:** Tự động loại bỏ các trường không cần thiết (`updatedAt`, `deletedAt`) và trường nhạy cảm (`password`).

### B. Tích hợp minh bạch (Transparent Integration)
Thay vì bắt các Developer phải tự gọi hàm Diff ở mỗi module, logic này được gia cố trực tiếp vào `DrizzleAuditLogService`.

```typescript
// Logic xử lý tại log()
if (before && after && typeof before === 'object' && typeof after === 'object') {
    const diff = ObjectDiff.calculate(before, after);
    if (diff) {
        before = diff.before;
        after = diff.after;
    }
}
```

## 3. Quy trình Triển khai (Deployment Steps)
1.  **Phase 1:** Khởi tạo `object-diff.util.ts` và bộ unit test tương ứng.
2.  **Phase 2:** Cập nhật inject logic vào `DrizzleAuditLogService.ts`.
3.  **Phase 3:** Chạy bộ test hồi quy (Regression Testing) cho các module CRM, User Account để đảm bảo log vẫn được ghi đúng.
4.  **Phase 4:** Cập nhật Hiến pháp dự án (ADR 006) và Changelog.

## 4. Kết quả (Results)
- **Dung lượng lưu trữ:** Một bản ghi đổi trạng thái Lead giảm từ ~5KB xuống còn ~200B.
- **Tính minh bạch:** Log ghi rõ: `{"status": "OLD"} -> {"status": "NEW"}`.
- **Hiệu năng:** Việc tính toán Diff diễn ra trong block `setImmediate`, không làm chậm Response của người dùng.

---
*Tài liệu được tạo tự động bởi Antigravity AI.*
