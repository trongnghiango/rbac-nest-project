Đây là bản đồ chi tiết luồng chạy (Flow) của một Request trong hệ thống của bạn. Tôi sẽ lấy ví dụ cụ thể là API **Đăng ký (Register)** vì nó đi qua đầy đủ các lớp nhất (Validation, Service, Transaction, DB, Mapper).

---

### KỊCH BẢN: User gửi Request `POST /api/auth/register`

#### 1. Khởi động & Cấu hình (Initialization)
Request đi vào Server, NestJS thiết lập môi trường.
*   **File:** `src/bootstrap/main.ts`
    *   **Hàm:** `bootstrap()`
    *   **Tác vụ:**
        *   Gắn Global Prefix `/api`.
        *   Kích hoạt `ValidationPipe` (từ `CoreModule`).
        *   Kích hoạt `HttpExceptionFilter` (từ `CoreModule`).
        *   Kích hoạt `TransformResponseInterceptor` (từ `CoreModule`).

---

#### 2. Lớp Bảo vệ (Guards) - "Anh là ai?"
Trước khi vào Controller, Request bị chặn lại để kiểm tra.
*   **File:** `src/modules/auth/infrastructure/guards/jwt-auth.guard.ts`
    *   **Hàm:** `canActivate()`
    *   **Tác vụ:** Kiểm tra xem route này có gắn Decorator `@Public()` không.
    *   **Kết quả:** Vì `register` có `@Public()`, Guard cho phép đi tiếp (trả về `true`).

---

#### 3. Lớp Kiểm tra dữ liệu (Pipes & DTO) - "Dữ liệu sạch không?"
*   **File:** `src/modules/auth/infrastructure/dtos/auth.dto.ts`
    *   **Class:** `RegisterDto`
    *   **Tác vụ:** So khớp Body gửi lên với các luật (`@IsString`, `@MinLength`, `@IsEmail`).
    *   **Kết quả:** Nếu sai -> Ném lỗi `BadRequestException`. Nếu đúng -> Đi tiếp vào Controller.

---

#### 4. Lớp Điều phối (Controller) - "Gặp ai để xử lý?"
*   **File:** `src/modules/auth/infrastructure/controllers/auth.controller.ts`
    *   **Hàm:** `register(@Body() data: RegisterDto)`
    *   **Tác vụ:** Nhận dữ liệu sạch từ DTO, gọi xuống Service để xử lý nghiệp vụ.
    *   **Code:** `return this.authService.register(data);`

---

#### 5. Lớp Nghiệp vụ (Application Service) - "Xử lý logic chính"
Đây là bộ não của hệ thống.
*   **File:** `src/modules/auth/application/services/authentication.service.ts`
    *   **Hàm:** `register(data)`
    *   **Tác vụ 1:** Gọi `userRepository.findByUsername` để check trùng.
    *   **Tác vụ 2:** Hash password bằng `PasswordUtil`.
    *   **Tác vụ 3:** Khởi tạo Domain Entity: `new User(...)`.
    *   **Tác vụ 4 (Transaction):** Gọi `txManager.runInTransaction(...)`.

---

#### 6. Lớp Giao dịch (Infrastructure - Transaction) - "ACID"
*   **File:** `src/core/shared/infrastructure/persistence/drizzle-transaction.manager.ts`
    *   **Hàm:** `runInTransaction()`
    *   **Tác vụ:** Mở một Transaction của Drizzle (`db.transaction`). Truyền biến `tx` xuống cho các Repository con bên trong.

---

#### 7. Lớp Lưu trữ (Infrastructure - Repository & Mapper) - "Ghi xuống DB"
Logic bên trong Transaction Block.

**Bước 7.1: Lưu User**
*   **File:** `src/modules/user/infrastructure/persistence/drizzle-user.repository.ts`
    *   **Hàm:** `save(user, tx)`
*   **File:** `src/modules/user/infrastructure/persistence/mappers/user.mapper.ts`
    *   **Hàm:** `toPersistence(domain)`
    *   **Tác vụ:** Chuyển đổi Object `User` (Domain) -> Object JSON phẳng (Drizzle Schema).
*   **Quay lại Repo:** Thực hiện lệnh `tx.insert(users).values(...)`.

**Bước 7.2: Lưu Session**
*   **File:** `src/modules/auth/infrastructure/persistence/drizzle-session.repository.ts`
    *   **Hàm:** `create(session, tx)`
*   **File:** `src/modules/auth/infrastructure/persistence/mappers/session.mapper.ts`
    *   **Hàm:** `toPersistence(domain)`
*   **Quay lại Repo:** Thực hiện lệnh `tx.insert(sessions).values(...)`.

---

#### 8. Kết thúc Transaction & Trả về
*   Nếu mọi thứ OK: `AuthenticationService` trả về `{ accessToken, user }`.
*   Dữ liệu quay ngược lên `AuthController`.

---

#### 9. Lớp Phản hồi (Interceptor) - "Đóng gói quà"
Trước khi gửi về Client, dữ liệu đi qua Interceptor.
*   **File:** `src/core/interceptors/transform-response.interceptor.ts`
    *   **Hàm:** `intercept()`
    *   **Tác vụ:** Bọc dữ liệu gốc vào cấu trúc chuẩn:
        ```json
        {
          "success": true,
          "statusCode": 201,
          "message": "Success",
          "result": { ...dữ liệu từ controller... }
        }
        ```

---

#### 10. (Nếu có lỗi) Lớp Xử lý Lỗi (Exception Filter)
Nếu bất kỳ bước nào ở trên ném `throw new Error/Exception`.
*   **File:** `src/core/filters/http-exception.filter.ts`
    *   **Hàm:** `catch()`
    *   **Tác vụ:** Bắt lỗi, format lại thành JSON chuẩn (tránh lộ stack trace chết người), trả về HTTP Code tương ứng (400, 401, 500...).

---

### TÓM TẮT DÒNG CHẢY DỮ LIỆU

```mermaid
Client Request
   ⬇
Main (Bootstrap)
   ⬇
Guard (JwtAuthGuard) --> [Nếu chặn: Exception Filter]
   ⬇
Pipe (ValidationPipe) --> [Nếu sai: Exception Filter]
   ⬇
Controller (AuthController)
   ⬇
Service (AuthenticationService) --(Gọi)--> TransactionManager
   ⬇
   [Bên trong Transaction]
   Entities (User/Session Domain)
   ⬇
   Repository (DrizzleUserRepository) --(Gọi)--> Mapper (UserMapper)
   ⬇
   Database (PostgreSQL)
   ⬆
   (Trả kết quả ngược lại)
   ⬇
Interceptor (TransformResponseInterceptor)
   ⬇
Client Response (JSON)
```