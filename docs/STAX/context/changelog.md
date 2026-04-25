# 📝 NHẬT KÝ THAY ĐỔI & REFACTOR (CHANGES.MD)

File này ghi lại các quyết định quan trọng về kiến trúc và các đợt Refactor mã nguồn để đảm bảo hệ thống tuân thủ "Hiến pháp" backend.

---

## 🚀 [2026-04-25] - System Hardening & Knowledge Management

Một đợt nâng cấp toàn diện nhằm đảm bảo tính ổn định của dữ liệu lõi và chuẩn hóa tài liệu dự án.

### 1. Triển khai Strict Enum (Data Integrity)
*   **Thay đổi:** Chuyển đổi toàn bộ các trường `status` và `type` từ string sang `pgEnum` (Postgres) và TypeScript Enum.
*   **Lý do:** Loại bỏ hoàn toàn lỗi dữ liệu lỏng lẻo, đảm bảo báo cáo Business luôn chính xác 100%. Áp dụng cho: Organization, Lead, Contract, Finote.

### 2. Tối ưu Lead Intake & Payment Logic
*   **Lead Intake:** Sửa lỗi logic khi gặp khách lẻ đã tồn tại nhưng chưa có hồ sơ Doanh nghiệp (Organization). Hệ thống giờ đây tự động khởi tạo và móc nối chính xác.
*   **Payment Reconciliation:** Thêm lớp bảo vệ (Validation) chặn tuyệt đối việc gạch nợ vào các hóa đơn đã được thanh toán hoàn tất (PAID).

### 3. "Xanh hóa" hệ thống bài Test (Unit Testing)
*   **Hành động:** Hoàn thiện bộ Test Suite cho `LeadIntakeService` và `PaymentReconciliationService`.
*   **Kết quả:** Bao phủ toàn bộ các kịch bản thực tế và các trường hợp biên (Edge Cases) nguy hiểm.

### 4. Quy hoạch Trung tâm Tri thức (Knowledge Management)
*   **Hành động:** Thiết lập thư mục `docs/STAX/context/` làm "Bộ não" của dự án. 
*   **Dọn dẹp:** Gom toàn bộ tài liệu rải rác ở thư mục gốc (ARCHITECTURE.md, BACKEND.md...) vào trung tâm tri thức để dễ dàng quản lý và bàn giao.

---

## [2026-04-24] - Refactor Cơ chế Giao tiếp Cross-Module (Smell #6)

### 🚀 Thay đổi chính
1.  **Cập nhật ARCHITECTURE.md & BACKEND_CONTEXT.md:** Định nghĩa rõ ràng cơ chế **SYNC (Orchestration)** và **ASYNC (Choreography)**.
2.  **Xây dựng Domain Ports:** Tạo ra các Interface Service (`IUserAccountService`, `IRbacManageService`) tại tầng Domain của Module đích.
3.  **Refactor `CompanyImportService`:** Chuyển từ việc truy cập Repository trực tiếp sang gọi thông qua các Port Service.

### 🔍 Chi tiết kỹ thuật & Pattern áp dụng:
*   **Pattern: Inter-Module Domain Service Port:** Giúp tách biệt hoàn toàn Logic giữa 2 module. Module A chỉ gọi Port (Cổng) của Module B mà không cần biết Module B dùng DB gì (Drizzle, Prisma hay MongoDB).
*   **Lợi ích:** Tránh lỗi Circular Dependency (Vòng lặp phụ thuộc) và giúp Unit Test dễ dàng hơn.

---

## 🚀 [2026-04-24] - Final Cleanup: Nâng Cấp Chuẩn Premium

Đây là đợt dọn dẹp cuối cùng để chuẩn hóa toàn bộ dự án theo luật kiến trúc mới.

### 1. "Quét rác" Swagger khỏi tầng Nghiệp vụ (Clean Application Layer)
*   **Thay đổi:** Di chuyển Decorator `@ApiProperty` sang tầng `infrastructure`.
*   **Lý do:** Tầng Nghiệp vụ (Application/Domain) là bộ não, cần "sạch" và không được phụ thuộc vào công cụ bên ngoài (Swagger). Nếu sau này bỏ Swagger, logic nghiệp vụ vẫn giữ nguyên không phải sửa.

### 2. Cấm rò rỉ dữ liệu thô (Standardized Response Mapping)
*   **Thay đổi:** Thay `.toJSON()` bằng `UserResponseDto.fromDomain(user)`.
*   **Lý do:** Đây là nguyên tắc **Security by Design**. Cần có "Bộ lọc" (DTO) để chỉ định rõ ràng trường nào được phép gửi ra ngoài (ví dụ: giấu password, các trường nội bộ).

### 3. Chuẩn hóa Data Flow bằng Entity
*   **Thay đổi:** Dùng [FinoteAttachment Entity] thay cho `any`.
*   **Lý do:** Ép kiểu chặt chẽ ngay từ tầng Domain. Repository luôn biết chính xác nó đang lưu cái gì, giúp code tự giải thích (Self-documenting) và giảm thiểu bug runtime.

### 4. Quản lý Transaction "Tàng hình" (ALS Transaction)
*   **Thay đổi:** Chuyển sang dùng **Async Local Storage (ALS)**.
*   **Lý do:** Loại bỏ việc truyền tham số `tx` thủ công xuyên suốt các hàm. Giúp Interface cực kỳ sạch sẽ và lập trình viên không lo quên truyền transaction context.

---

## 🚀 [2026-04-24] - Architecture Hardening: Mapper & Global Cleanup

Đợt nâng cấp cuối cùng nhằm thực thi triệt để các quy tắc Tier 2 và làm sạch hoàn toàn tầng Application.

### 1. Thực thi Tier 2 Mapper cho Module `OrgStructure`
*   **Thay đổi:** Xây dựng [OrgStructureMapper] và cập nhật Repository để map dữ liệu Drizzle sang Domain Entity.
*   **Lý do:** Theo luật mới, Tier 2 không được phép ép kiểu trực tiếp (`as any`) từ DB Record. Phải có Mapper để đảm bảo tầng Domain không bị "vỡ" khi Database thay đổi cấu trúc bảng.
*   **Luận cứ:** Việc này giúp tách biệt hoàn toàn sự phụ thuộc (Decoupling). Entity của bạn giờ đây là "nguyên bản", không bị lẫn lộn với các field thừa của Database schema.

### 2. Tổng vệ sinh Swagger DTO (Module `Employee` & `OrgStructure`)
*   **Thay đổi:** Di chuyển `@ApiProperty` sang `infrastructure/dtos` cho tất cả các module còn lại.
*   **Lý do:** Đảm bảo toàn bộ dự án đồng nhất về mặt kiến trúc. Tầng Application giờ đây hoàn toàn "sạch" bóng dáng của thư viện bên ngoài.
*   **Luận cứ:** Tính nhất quán (Consistency) giúp các lập trình viên mới vào dự án dễ dàng nắm bắt quy tắc và không bị nhầm lẫn khi code các module khác nhau.

---

## 🚀 [2026-04-24] - Testing Foundation: Chiến lược và Unit Test mẫu

Thiết lập nền tảng cho việc kiểm thử tự động để bảo vệ các thành quả Refactor.

### 1. Ban hành tài liệu [TEST_STRATEGY.md]
*   **Thay đổi:** Xây dựng bộ quy tắc kiểm thử theo mô hình Kim tự tháp (Unit -> Integration -> E2E).
*   **Lý do:** Khi hệ thống ngày càng lớn, việc kiểm tra thủ công là không thể. Cần có "hàng rào bảo vệ" bằng code để phát hiện lỗi ngay lập tức.
*   **Luận cứ:** Test giúp code của chúng ta trở thành "Tài liệu sống", giúp các thành viên mới hiểu nghiệp vụ nhanh hơn thông qua việc đọc các kịch bản test.

### 2. Triển khai Unit Test mẫu cho `UserAccountService`
*   **Thay đổi:** Viết file [user-account.service.spec.ts] hoàn chỉnh.
*   **Kỹ thuật:** Sử dụng **Mocking** để giả lập Repository. Áp dụng **Data-Driven Testing** (truyền một danh sách đầu vào) để kiểm tra nhiều trường hợp dữ liệu chỉ trong 1 đoạn code.
*   **Lợi ích:** Đây là ví dụ mẫu (Template) để team có thể sao chép và áp dụng cho các module khác.

---

## 🚀 [2026-04-24] - Advanced Testing: Quy trình Import phức tạp

Triển khai Unit Test cho `CompanyImportService` - Orchestrator phức tạp nhất dự án.

### 1. Kỹ thuật Mocking đa tầng (Multi-Dependency Mocking)
*   **Thay đổi:** Giả lập cùng lúc 5 Port/Repository (`IOrgStructureRepository`, `IUserAccountService`, `IEmployeeRepository`, v.v.).
*   **Lý do:** Giúp test cô lập hoàn toàn logic của quy trình Import mà không cần quan tâm đến lỗi từ DB hay các module khác.
*   **Chi tiết:** Sử dụng `jest.fn()` để kiểm soát giá trị trả về của các hàm tìm kiếm và lưu trữ, cho phép giả định các kịch bản (ví dụ: tạo phòng ban cha thành công rồi mới tìm thấy con).

### 2. Kiểm chứng luồng nghiệp vụ (Workflow Validation)
*   **Thay đổi:** Viết test cover cả trường hợp dữ liệu CSV thiếu thông tin hoặc sai định dạng.
*   **Lợi ích:** Đảm bảo hệ thống có khả năng tự phục hồi hoặc bỏ qua dữ liệu lỗi một cách an toàn (Graceful handling) thay vì treo toàn bộ tiến trình.

---

## 🚀 [2026-04-24] - Seed Data Hardening: Công cụ "Xưởng hạt giống"

Nâng cấp bộ công cụ Seeding để đảm bảo tính sẵn sàng cao và độc lập dữ liệu.

### 1. Refactor `seed-data-transformer.ts`
*   **Thay đổi:** Nhúng trực tiếp dữ liệu thô (`RAW_DATA`) vào mã nguồn của tool.
*   **Lý do:** Loại bỏ sự phụ thuộc vào file Excel (`.xlsx`) bên ngoài vốn dễ bị mất hoặc lỗi định dạng. Giúp bất kỳ ai trong team cũng có thể tạo lại bộ Seed chuẩn chỉ bằng 1 câu lệnh.
*   **Luận cứ:** Tính tự đóng gói (Self-contained) là yếu tố tiên quyết cho môi trường phát triển (Local Development) ổn định.

---

## 🚀 [2026-04-24] - Accounting Overhaul: Kiến trúc Kế toán 4 lớp

Đây là bước ngoặt lớn về mặt nghiệp vụ để hệ thống STAX có thể xử lý các luồng tài chính phức tạp, chống thất thoát.

### 1. Phân tách Hóa đơn & Dòng tiền (Accrual vs Cash Flow)
*   **Thay đổi:** Thêm bảng `cash_transactions` (Sổ Quỹ) và `finote_items` (Chi tiết hóa đơn).
*   **Lý do:** Giải quyết bài toán một hóa đơn có nhiều loại phí (phí kế toán + phí phát sinh) và một lần khách trả tiền có thể gạch nợ cho nhiều hóa đơn khác nhau.
*   **Chi tiết kiến trúc:**
    -   **Lớp 1 (Header):** `finotes` quản lý tổng nợ.
    -   **Lớp 2 (Items):** `finote_items` quản lý chi tiết các dịch vụ.
    -   **Lớp 3 (Cash Flow):** `cash_transactions` quản lý tiền thực tế vào/ra.
    -   **Lớp 4 (Automation):** `billing_templates` quản lý thu phí định kỳ hằng tháng.

### 2. Sửa lỗi "Tàng hình" mã nguồn (.gitignore Fix)
*   **Thay đổi:** Sửa `database/` thành `/database/` trong file `.gitignore`.
*   **Lý do:** Phát hiện quy tắc cũ đang làm Git bỏ qua toàn bộ thư mục `src/database/` (chứa toàn bộ Schema). Việc này cực kỳ nguy hiểm vì làm mất dấu vết các thay đổi kiến trúc quan trọng trên Git.

---

### 💡 Tổng kết triết lý Refactor:
*"Chúng ta không viết code để máy chạy, chúng ta viết code để con người (chính chúng ta sau 6 tháng nữa) có thể đọc và hiểu được. Một hệ thống tốt là hệ thống mà khi bạn thay đổi một module, bạn không sợ làm hỏng cả thế giới còn lại."*

---

## 🚀 [2026-04-24] - Documentation Harmonization: Đồng bộ hóa "Hiến pháp"

Đợt tổng kiểm kê và cập nhật toàn bộ hệ thống tài liệu để khớp với kiến trúc thực tế.

### 1. Đồng bộ hóa Sơ đồ thực thể (ERD)
*   **Thay đổi:** Cập nhật file thiết kế gốc tại `docs/STAX/20260423-stax-architecture-v2.md` để phản ánh đúng cấu trúc 4 lớp của Module Kế toán (Header -> Items -> Payments -> Cash Trans).
*   **Lý do:** Tránh việc tài liệu bị "lạc hậu" so với code, gây khó khăn cho việc mở rộng sau này.

### 2. Kiện toàn Chiến lược Vận hành
*   **Cập nhật:** Hoàn thiện `ARCHITECTURE.md` và `BACKEND_CONTEXT.md` với các khái niệm mới về **Flow-based Automation** và **Audit Mapping**.
*   **Luận cứ:** Tài liệu chính là "mã nguồn của tư duy". Khi tư duy thông suốt, việc viết code sẽ trở nên chuẩn xác.

