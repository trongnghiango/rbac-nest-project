# 📝 NHẬT KÝ THAY ĐỔI & REFACTOR (CHANGES.MD)

File này ghi lại các quyết định quan trọng về kiến trúc và các đợt Refactor mã nguồn để đảm bảo hệ thống tuân thủ "Hiến pháp" backend.

---

## 🛡️ [2026-04-26] - Audit Log System: Hoàn thiện Kiến trúc Giám sát

Thiết lập hệ thống nhật ký hành động toàn diện (Audit Log) cho toàn dự án STAX.

### 1. Kiến trúc Tier 1 (Foundation)
*   **AUDIT_LOG_PORT:** Định nghĩa interface chuẩn (`IAuditLogService`) cho toàn hệ thống.
*   **DrizzleAuditLogService:** Implementation sử dụng Drizzle ORM, hỗ trợ Async Local Storage (ALS) để tự động truy vết Actor và Transaction.
*   **Schema `audit_logs`:** Thiết kế tập trung với khả năng lưu vết thay đổi dữ liệu chi tiết (`before/after` JSONB).

### 2. Tích hợp Nghiệp vụ toàn diện (Core Workflows)
Đã tích hợp Audit Log vào 4 luồng nghiệp vụ quan trọng nhất:
*   **CRM:** Chốt Lead thành công (`LEAD.CLOSE_WON`).
*   **Accounting:** Gạch nợ hóa đơn (`PAYMENT.ALLOCATED`).
*   **RBAC:** Gán quyền cho người dùng (`RBAC.ROLE_ASSIGNED`).
*   **Identity:** Khởi tạo tài khoản mới (`USER.PROVISIONED`).

### 3. Cập nhật & Gia cố Hệ thống Test
*   **Unit Testing:** Cập nhật toàn bộ các bộ test cũ (`PaymentReconciliation`, `UserAccount`) để tương thích với kiến trúc mới.
*   **New Tests:** Bổ sung unit test cho `DrizzleAuditLogService` và `LeadWorkflowService`.
*   **E2E Verify:** Script kiểm chứng thực tế ghi/đọc log từ Database thành công.

---

## 🗄️ [2026-04-26] - Legacy CRM Data Migration: Hoàn thành Phase 1→4

Thực thi toàn bộ pipeline di cư dữ liệu từ file CSV/XLSX sang STAX DB. Môi trường: Dev/Test.

### Schema Changes
*   **`organizations`**: Thêm cột `metadata JSONB` (Hybrid Storage Pattern - ADR 003)
*   **`contacts`**: Thêm cột `metadata JSONB`
*   **`leads`**: Thêm cột `metadata JSONB` + enum `ZALO` vào `leadSourceEnum`
*   **`contracts`**: Thêm cột `metadata JSONB`

### migration-results
| Bảng | Records | Tỷ lệ lỗi |
|------|---------|------------|
| organizations | 202 | 4.3% (dup email constraint) |
| contacts | 202 | 4.3% (dup email) |
| leads | 1,172 | 0% |
| contracts | 158 | 0% |
| finotes | 363 | 0% |

---

## 🚀 [2026-04-25] - System Hardening & Knowledge Management

Một đợt nâng cấp toàn diện nhằm đảm bảo tính ổn định của dữ liệu lõi và chuẩn hóa tài liệu dự án.

### 1. Triển khai Strict Enum (Data Integrity)
*   **Thay đổi:** Chuyển đổi toàn bộ các trường `status` và `type` từ string sang `pgEnum` (Postgres) và TypeScript Enum.
*   **Lý do:** Loại bỏ hoàn toàn lỗi dữ liệu lỏng lẻo, đảm bảo báo cáo Business luôn chính xác 100%. Áp dụng cho: Organization, Lead, Contract, Finote.

### 2. Tên hóa quy trình tài liệu
*   **Hành động:** Thiết lập thư mục `docs/STAX/context/` làm "Bộ não" của dự án. 
*   **Dọn dẹp:** Gom toàn bộ tài liệu rải rác vào trung tâm tri thức để dễ dàng quản lý và bàn giao.

---

### 💡 Tổng kết triết lý Refactor:
*"Chúng ta không viết code để máy chạy, chúng ta viết code để con người có thể đọc và hiểu được. Một hệ thống tốt là hệ thống mà khi bạn thay đổi một module, bạn không sợ làm hỏng cả thế giới còn lại."*

---
*Tài liệu được cập nhật ngày 26/04/2026 bởi Antigravity AI.*
