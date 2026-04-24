# 📝 NHẬT KÝ THAY ĐỔI & REFACTOR (CHANGES.MD)

File này ghi lại các quyết định quan trọng về kiến trúc và các đợt Refactor mã nguồn để đảm bảo hệ thống tuân thủ "Hiến pháp" backend.

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

### 💡 Tổng kết triết lý Refactor:
*"Chúng ta không viết code để máy chạy, chúng ta viết code để con người (chính chúng ta sau 6 tháng nữa) có thể đọc và hiểu được. Một hệ thống tốt là hệ thống mà khi bạn thay đổi một module, bạn không sợ làm hỏng cả thế giới còn lại."*
