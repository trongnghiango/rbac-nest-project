Chào bạn, tôi đã cập nhật lại tài liệu theo đúng yêu cầu: **Giữ tên file gọn gàng (`.port.ts`, `.dto.ts`)**, chỉ áp dụng quy tắc đặt tên (Prefix/Suffix) cho **Class và Interface**.

Đây là tài liệu quy chuẩn chính thức cho dự án:

---

# 📖 TÀI LIỆU QUY CHUẨN: INTERFACE & DTO ARCHITECTURE

## 1. Nguyên Tắc Cốt Lõi
1.  **Tách biệt Data và Behavior:** Class chứa dữ liệu thì không chứa logic. Class chứa logic thì không giữ dữ liệu (state).
2.  **Giao tiếp qua Port:** Các Module không gọi trực tiếp Class của nhau, mà gọi qua Interface (Hợp đồng).
3.  **Dependency Injection:** Sử dụng Token trùng tên với Interface để code gọn gàng nhất.

---

## 2. Quy Ước Đặt Tên & Cấu Trúc File

### A. Dữ Liệu (Data Transfer Object)
Dùng để đóng gói dữ liệu mang đi giữa các lớp/module.
*   **Tên File:** `<tên-nghiệp-vụ>.dto.ts`
*   **Tên Class:** `<TênNghiệpVụ>Dto`
*   **Vị trí:** `src/modules/<module>/application/dtos/`
*   **Ví dụ:**
    *   File: `user-summary.dto.ts`
    *   Class: `UserSummaryDto`

### B. Hành Vi Công Khai (Inbound Port)
Là hợp đồng để các Module khác gọi vào.
*   **Tên File:** `<tên-nghiệp-vụ>.port.ts` (Giữ tên file ngắn gọn)
*   **Tên Interface:** `I<TênNghiệpVụ>Service`
*   **Vị trí:** `src/modules/<module>/application/ports/`
*   **Ví dụ:**
    *   File: `user.port.ts`
    *   Interface: `IUserService`

### C. Hành Vi Nội Bộ (Outbound Port)
Là hợp đồng để giao tiếp với Database/Hạ tầng.
*   **Tên File:** `<tên-nghiệp-vụ>.repository.ts`
*   **Tên Interface:** `I<TênNghiệpVụ>Repository`
*   **Vị trí:** `src/modules/<module>/domain/repositories/`
*   **Ví dụ:**
    *   File: `user.repository.ts`
    *   Interface: `IUserRepository`

---

## 3. Kỹ thuật Dependency Injection (DI Token)

Để việc Inject trở nên "trong suốt" (không cần nhớ 2 tên khác nhau cho Token và Interface), ta sử dụng kỹ thuật **Declaration Merging** (Gộp khai báo) của TypeScript.

**Quy tắc:** Khai báo `const` (Token) và `interface` (Type) **cùng tên** trong file Port.

```typescript
// Token (Runtime)
export const IUserService = Symbol('IUserService');

// Type (Compile-time)
export interface IUserService {
  ...
}
```

Khi dùng: `@Inject(IUserService) private service: IUserService`.

---

## 4. Minh Họa Code (Full Flow)

Ví dụ: Module **Booking** cần lấy thông tin từ Module **User**.

### Bước 1: Định nghĩa Dữ liệu (DTO)
*File: `src/modules/user/application/dtos/user.dto.ts`*

```typescript
export class UserDto {
  id: number;
  email: string;
  fullName: string;
}
```

### Bước 2: Định nghĩa Hành vi (Port & Token)
*File: `src/modules/user/application/ports/user.port.ts`*

```typescript
import { UserDto } from '../dtos/user.dto';

// 1. Token định danh (Runtime)
export const IUserService = Symbol('IUserService');

// 2. Interface hành vi (Compile-time)
export interface IUserService {
  getUserSummary(id: number): Promise<UserDto | null>;
}
```

### Bước 3: Thực thi (Implementation)
*File: `src/modules/user/application/services/user.service.ts`*

```typescript
import { Injectable } from '@nestjs/common';
import { IUserService } from '../ports/user.port'; // Import cả Token & Interface

@Injectable()
export class UserService implements IUserService {
  async getUserSummary(id: number): Promise<UserDto | null> {
    // Logic lấy dữ liệu từ DB, map sang DTO
    return { id, email: 'test@mail.com', fullName: 'Nguyen Van A' };
  }
}
```

### Bước 4: Đăng ký Module (Provider)
*File: `src/modules/user/user.module.ts`*

```typescript
import { Module } from '@nestjs/common';
import { IUserService } from './application/ports/user.port';
import { UserService } from './application/services/user.service';

@Module({
  providers: [
    {
      provide: IUserService, // Dùng Token (Symbol)
      useClass: UserService, // Class thực thi
    },
  ],
  exports: [IUserService], // Export Token ra ngoài
})
export class UserModule {}
```

### Bước 5: Public qua Cổng Làng (Index)
*File: `src/modules/user/index.ts`*

```typescript
// Chỉ export DTO và Port
export * from './application/dtos/user.dto';
export * from './application/ports/user.port';
export { UserModule } from './user.module';
```

### Bước 6: Sử dụng tại Module khác
*File: `src/modules/booking/booking.service.ts`*

```typescript
import { Injectable, Inject } from '@nestjs/common';
// Import từ module User (gọn gàng)
import { IUserService, UserDto } from '../../user'; 

@Injectable()
export class BookingService {
  constructor(
    // Inject cực đẹp: Tên biến và kiểu khớp nhau
    @Inject(IUserService) private readonly userService: IUserService
  ) {}

  async createBooking(userId: number) {
    const user: UserDto = await this.userService.getUserSummary(userId);
    console.log(user.fullName);
  }
}
```

---

## 5. Tổng kết
Với cấu trúc này:
1.  **File name:** Ngắn gọn, dễ tìm (`user.port.ts`, `user.dto.ts`).
2.  **Interface name:** Rõ nghĩa (`IUserService`, `UserDto`).
3.  **Dependency Injection:** Không magic string, không thừa code (`@Inject(IUserService)`).