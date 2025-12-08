Tài liệu này chia làm 2 phần:
1.  **So găng các ORM**: Tại sao chọn cái này, bỏ cái kia.
2.  **Kỹ thuật Mapping**: Biến dữ liệu phẳng (DB) thành dữ liệu lồng (Code) và ngược lại.

---

# PHẦN 1: SO GĂNG CÁC ORM TRONG BỐI CẢNH DDD

Tiêu chí so sánh: Khả năng hỗ trợ **Value Object** (Đối tượng giá trị không có ID) và **Embedding** (Nhúng dữ liệu vào bảng cha).

| Tiêu chí | **TypeORM** (Lão làng) | **Prisma** (An toàn) | **Drizzle** (Tốc độ & Kiểm soát) |
| :--- | :--- | :--- | :--- |
| **Triết lý** | **OOP First.** Cố gắng biến DB thành Object. Dùng Decorator (Magic). | **Schema First.** Định nghĩa file schema riêng, generate ra client. | **SQL First.** Nếu bạn biết SQL, bạn biết Drizzle. Không Magic. |
| **Xử lý Value Object** | **Tốt nhất.** Dùng `@Column(() => Address)` nó tự động trải phẳng ra cột. | **Kém.** Phải khai báo thủ công từng cột trong schema hoặc dùng JSON (mất tính năng query tốt). | **Khá.** Cho phép tái sử dụng cụm cột (spread columns) nhưng không tự map vào object. |
| **Mapping** | **Tự động.** Query xong có ngay object lồng nhau. | **Thủ công.** Query xong ra dữ liệu phẳng, phải tự code để gom lại. | **Thủ công.** Query xong ra dữ liệu phẳng, phải viết Mapper. |
| **Hiệu năng** | Trung bình (do cơ chế Reflection). | Khá, nhưng query engine nặng nề (Rust binary). | **Siêu nhanh.** Gần như native SQL driver. |
| **Phù hợp với ai?** | Người thích nhàn, thích code kiểu Java/C#, chấp nhận "ma thuật". | Người thích type-safe tuyệt đối, dự án đơn giản, ít Value Object phức tạp. | **Người thích kiểm soát DB, thích nhìn rõ cấu trúc SQL, chấp nhận viết thêm code Mapper.** |

👉 **Kết luận:** Với phong cách "Thiết kế DB trước, Code sau" của đại ca, **Drizzle ORM** là lựa chọn số 1.

---

# PHẦN 2: KỸ THUẬT MAPPING (FLAT DATA vs NESTED LOGIC)

Đây là bí kíp để kết hợp sự chặt chẽ của SQL với sự linh hoạt của OOP.

### Mô hình tư duy
*   **Database (Infrastructure Layer):** Nơi lưu trữ. Cần tối ưu cho việc đánh Index, Query, Join. Dữ liệu phải **PHẲNG (FLAT)**.
*   **Code (Domain Layer):** Nơi xử lý nghiệp vụ. Cần tối ưu cho việc Validate, Bao đóng (Encapsulation). Dữ liệu phải **LỒNG NHAU (NESTED)**.

### Ví dụ thực chiến
Giả sử ta có cấu trúc lồng 3 cấp: `User` (Entity) -> chứa `Profile` (VO) -> chứa `Address` (VO).

#### BƯỚC 1: Xây dựng Domain (Code Logic - Lồng lộn)
Nơi chứa logic nghiệp vụ, không quan tâm DB là gì.

```typescript
// --- FILE: src/domain/user.entity.ts ---

// Cấp 3: Value Object nhỏ nhất
export class Address {
  constructor(
    public readonly street: string,
    public readonly city: string
  ) {
    if (!city) throw new Error("City không được để trống");
  }
}

// Cấp 2: Value Object chứa Address
export class Profile {
  constructor(
    public readonly displayName: string,
    public readonly address: Address // <--- Lồng Address vào đây
  ) {}
}

// Cấp 1: Entity (Aggregate Root) - Thằng to nhất
export class User {
  constructor(
    public readonly id: number,
    public readonly username: string,
    public profile: Profile // <--- Lồng Profile vào đây
  ) {}

  // Logic nghiệp vụ: Thay đổi địa chỉ
  moveTo(newStreet: string, newCity: string) {
    // Thay thế toàn bộ VO Address cũ bằng cái mới (Immutable)
    const newAddress = new Address(newStreet, newCity);
    // Tái tạo Profile với Address mới
    this.profile = new Profile(this.profile.displayName, newAddress);
  }
}
```

#### BƯỚC 2: Xây dựng Schema (Database - Phẳng lì)
Nơi định nghĩa bảng SQL bằng Drizzle.

```typescript
// --- FILE: src/infrastructure/drizzle/schema.ts ---
import { pgTable, serial, text } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  username: text('username').notNull(),
  
  // --- Flattening (Trải phẳng) Profile & Address ra đây ---
  // Không có bảng profile hay address riêng
  
  profileDisplayName: text('profile_display_name'), // Của Profile
  addrStreet: text('addr_street'),                  // Của Address (nằm trong Profile)
  addrCity: text('addr_city'),                      // Của Address (nằm trong Profile)
});
```

#### BƯỚC 3: Xây dựng Mapper (Cầu nối)
Đây là phần quan trọng nhất để chuyển đổi qua lại.

```typescript
// --- FILE: src/infrastructure/mappers/user.mapper.ts ---
import { User, Profile, Address } from '../../domain/user.entity';
import { InferSelectModel } from 'drizzle-orm';
import { users } from '../drizzle/schema';

// Lấy kiểu dữ liệu trả về từ Drizzle (Dạng phẳng)
type UserRecord = InferSelectModel<typeof users>;

export class UserMapper {
  
  /**
   * CHIỀU RA: Từ Database (Phẳng) -> Domain (Lồng)
   * Dùng khi thực hiện câu lệnh SELECT
   */
  static toDomain(record: UserRecord): User {
    // 1. Nhặt cột tạo Address (Cấp nhỏ nhất)
    const address = new Address(
      record.addrStreet || '', // Xử lý null nếu cần
      record.addrCity || ''
    );

    // 2. Nhặt cột tạo Profile (Cấp giữa)
    const profile = new Profile(
      record.profileDisplayName || '',
      address // Nhét cục address vừa tạo vào
    );

    // 3. Tạo Entity User hoàn chỉnh
    return new User(
      record.id,
      record.username,
      profile
    );
  }

  /**
   * CHIỀU VÀO: Từ Domain (Lồng) -> Database (Phẳng)
   * Dùng khi thực hiện INSERT hoặc UPDATE
   */
  static toPersistence(entity: User) {
    // Xé lẻ object ra để nhét vào từng cột tương ứng
    return {
      id: entity.id,
      username: entity.username,
      
      // Chọc sâu vào object để lấy giá trị (Dot notation)
      profile_display_name: entity.profile.displayName,
      addr_street: entity.profile.address.street,
      addr_city: entity.profile.address.city,
    };
  }
}
```

#### BƯỚC 4: Sử dụng trong Repository
Lúc này Repository chỉ việc gọi Mapper là xong.

```typescript
// Code giả mã trong Repository
async findById(id: number): Promise<User | null> {
    const record = await db.select().from(users).where(eq(users.id, id));
    if (!record) return null;
    
    // Biến data phẳng thành object xịn
    return UserMapper.toDomain(record); 
}

async save(user: User) {
    // Biến object xịn thành data phẳng để lưu
    const flatData = UserMapper.toPersistence(user);
    await db.insert(users).values(flatData);
}
```

### Tóm lại lợi ích của cách làm này:

1.  **Clean Code:** Domain Entity sạch bong, không dính tí decorator `@Column` hay logic database nào.
2.  **SQL Optimal:** Database được thiết kế chuẩn dạng bảng, index ngon lành, không bị phụ thuộc vào cấu trúc object.
3.  **Thay đổi dễ dàng:**
    *   Đổi tên cột trong DB? -> Chỉ sửa file `schema.ts` và `mapper.ts`. Code logic không ảnh hưởng.
    *   Đổi cấu trúc Object? -> Chỉ sửa `entity.ts` và `mapper.ts`. Database không ảnh hưởng (trừ khi cần thêm cột mới).
    