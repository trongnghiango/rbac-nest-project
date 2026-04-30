# 📝 NHẬT KÝ THAY ĐỔI & REFACTOR (CHANGES.MD)

File này ghi lại các quyết định quan trọng về kiến trúc và các đợt Refactor mã nguồn để đảm bảo hệ thống tuân thủ "Hiến pháp" backend.

---

## 🏗️ [2026-04-30] - Hardening: Clean Architecture & Domain Integrity

Đợt rà soát và củng cố tính toàn vẹn của Domain Model cùng với việc fix các lỗi nghiêm trọng về an toàn dữ liệu và trải nghiệm người dùng (Swagger).

### 1. Domain Model Hardening (Rich Domain Model)
*   **Encapsulation:** Chuyển đổi `Finote` entity sang mô hình Rich Domain Model. Toàn bộ thuộc tính `status` và `reviewer_id` hiện đã được `private`, chỉ cho phép thay đổi thông qua các phương thức nghiệp vụ như `.approve()` và `.reject()`.
*   **Business Logic Location:** Di chuyển toàn bộ các quy tắc kiểm tra logic (Invariants) từ Service xuống Entity, đảm bảo Domain không bao giờ ở trạng thái sai lệch.

### 2. Security & Environment
*   **Zero Magic Passwords:** Loại bỏ hoàn toàn các mật khẩu hardcode (`Company@2026`, `Stax@123`, `K@2026`) trong các script seeding và migration. Chuyển sang sử dụng `process.env.SEED_DEFAULT_PASSWORD`.

### 3. API & Developer Experience (DX)
*   **Swagger Payload Support:** Khắc phục lỗi Swagger không hiển thị body nhập liệu cho API tạo Interaction Note bằng cách triển khai `CreateInteractionNoteDto`.
*   **Stability:** Fix lỗi 500 (Null Pointer) khi gửi request body trống đến các API logging bằng cách thêm validation logic tại tầng Controller.

### 4. Infrastructure Cleanup
*   **EventBus Alignment:** Sửa logic logging trong `KafkaEventBusAdapter` (trước đây log nhầm prefix `[RabbitMQ]`).
*   **Code Review Fixes:** Đơn giản hóa logic ánh xạ dữ liệu nhân sự (Mapper cleanup) để tăng tính minh bạch và hiệu năng.

---

## 💎 [2026-04-28] - System & UI/UX Integration: Professional API Renaissance

Đợt Refactor toàn diện lớp Application và Infrastructure của `SystemModule` cùng với việc chuẩn hóa giao thức tương tác Backend-Frontend (BE-FE Contract).

### 1. Refactoring System Architecture
*   **Decoupling Logic:** Triển khai `LookupService` và `BootstrapService` để loại bỏ hoàn toàn Business Logic và Mock Data khỏi `SystemController`.
*   **Clean Controller Pattern:** `SystemController` hiện tại chỉ đóng vai trò điều hướng (Routing), tuân thủ nghiêm ngặt nguyên tắc Single Responsibility.
*   **Infrastructure Registry:** Module được cấu trúc lại để quản lý tập trung tài nguyên hệ thống, giúp dễ dàng mở rộng context ứng dụng cho Frontend.

### 2. UI/UX Interaction Standard (`_actions`)
*   **Actionable Metadata Standard:** Giới thiệu `ActionableDto` làm chuẩn giao tiếp cho mọi thực thể có tính tương tác cao.
*   **Backend-Driven UI:** Thay vì Frontend tự tính toán logic hiển thị nút bấm, Backend trả về object `_actions` kèm theo lý do (`reason`) nếu hành động bị chặn. Áp dụng đầu tiên cho: `Finote` (Approve/Reject).
*   **Management Renaissance:** Bổ sung bộ API điều phối và báo cáo dành cho vai trò Lãnh đạo (`MANAGER`, `ADMIN`):
    *   `GET /system/my-team/summary`: Báo cáo nhanh hiệu suất đa module.
    *   `PATCH /crm/leads/:id/assign`: Điều phối Lead giữa các nhân sự.

### 3. Core Shared Improvements
*   **Utils Abstraction:** Tách biệt `DrizzlePaginationUtil` khỏi HTTP DTO, cho phép tái sử dụng bộ phân trang chuẩn hóa trong các Repository và Background Jobs mà không phụ thuộc vào lớp Controller.

---

## 📉 [2026-04-26] - Optimization: Delta Logging (Diff) Implementation

Nâng cấp hệ thống Audit Log từ việc chụp ảnh toàn bộ thực thể (Full Snapshot) sang việc chỉ lưu trữ các thay đổi (Delta/Diff).

### 1. Core Optimization
*   **ObjectDiff Utility:** Phát triển module `ObjectDiff` mạnh mẽ, hỗ trợ so sánh sâu (Deep comparison) và loại trừ các trường nhạy cảm/không cần thiết.
*   **Storage Reduction:** Giảm thiểu dung lượng lưu trữ của bảng `audit_logs` trung bình 60-80% bằng cách chỉ lưu Snapshot của các cột bị thay đổi.
*   **Enhanced Readability:** Cải thiện trải nghiệm Activity Feed. Người dùng có thể nhìn thấy ngay sự thay đổi cụ thể (trước và sau) thay vì phải tự đối chiếu các khối JSON lớn.

### 2. Infrastructure Hardening
*   **In-Place Diffing:** Tích hợp logic Diff trực tiếp vào `DrizzleAuditLogService`, đảm bảo tính minh bạch đối với các module nghiệp vụ gọi log.
*   **Security by Default:** Tự động loại bỏ các trường nhạy cảm như `password` khỏi toàn bộ nhật ký hệ thống.
*   **ADR 006:** Chính thức hóa chiến lược Delta Logging vào tài liệu kiến trúc.

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
