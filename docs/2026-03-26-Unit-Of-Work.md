Tư duy kiến trúc ở mức **Senior/Architect**. 
- Việc nhận ra sự quá tải của `Service` khi hệ thống phình to.
- Tách các luồng nghiệp vụ phức tạp. 
- Gọi chéo nhiều module thành các **Use Case**, 
Việc kết hợp với pattern **Unit of Work (UoW)** là chuẩn mực cao nhất của **Clean Architecture** và **Domain-Driven Design (DDD)**.

## Chi tiết về **Unit of Work**, cách nó vận hành, và cách áp dụng thực tế vào chính source code.

---

### 1. UNIT OF WORK (UoW) LÀ GÌ? TẠI SAO PHẢI DÙNG NÓ?

#### Vấn đề (Nỗi đau của hệ thống Micro-services / Modular):
Giả sử bạn có một luồng: **"Tiếp nhận Bác sĩ mới"**. Luồng này cần gọi 3 module:
1. Gọi `UserModule` để tạo tài khoản đăng nhập.
2. Gọi `RbacModule` để gán quyền "Bác sĩ".
3. Gọi `EmployeeModule` để tạo hồ sơ nhân sự.

Nếu bạn viết code tuần tự, hệ thống chạy đến bước 1 (Tạo tài khoản OK), bước 2 (Gán quyền OK), nhưng đến **bước 3 (Tạo hồ sơ) thì DB bị lỗi** (do trùng mã nhân viên). 
👉 **Hậu quả:** Trong DB bị thừa ra một tài khoản User và Role, nhưng không có hồ sơ nhân viên. Dữ liệu bị rác và mất tính toàn vẹn (Data Inconsistency).

#### Giải pháp - Unit of Work (Đơn vị công việc):
**Unit of Work** là một Design Pattern đảm bảo rằng: **"Tất cả các hành động ghi vào Database trong cùng một Use Case phải được xem như MỘT ĐƠN VỊ DUY NHẤT"**. 
* Nếu tất cả đều thành công ➡️ **Commit** (Lưu vĩnh viễn vào DB).
* Nếu **CHỈ CẦN 1 BƯỚC THẤT BẠI** ➡️ **Rollback** (Hủy bỏ toàn bộ, DB trở về trạng thái y như lúc chưa gọi Use Case).

Trong thế giới Database, UoW chính là vỏ bọc (Abstraction) của **Database Transaction**.

---

### 2. BẠN ĐÃ CÓ SẴN UNIT OF WORK TRONG CODE!

Thật tuyệt vời là trong thư mục `src/core/shared` của bạn, bạn đã định nghĩa sẵn Pattern này thông qua interface `ITransactionManager`.

```typescript
// Đây chính là Abstract Unit of Work của bạn
export interface ITransactionManager {
  runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T>;
}
```

Bây giờ, chúng ta sẽ biến nó thành một **Use Case** hoàn chỉnh.

---

### 3. THỰC HÀNH: ÁP DỤNG UoW VÀO USE CASE THỰC TẾ

Chúng ta sẽ tạo một Use Case: `OnboardEmployeeUseCase`. Nó sẽ điều phối 3 Repositories thuộc 3 Module khác nhau.

#### Bước 3.1: Đảm bảo các Repository đều nhận tham số `tx` (Transaction)
Để UoW hoạt động, các module khi ghi dữ liệu không được dùng connection DB mặc định, mà **phải dùng chung một kết nối Transaction (`tx`)**. Trong code của bạn đã làm rất tốt việc này:

```typescript
// Ví dụ IUserRepository của bạn đã có (src/modules/user/domain/repositories/user.repository.ts)
save(user: User, tx?: Transaction): Promise<User>;

// IEmployeeRepository cũng phải có
save(data: any, tx?: Transaction): Promise<any>;
```

#### Bước 3.2: Viết Use Case điều phối (Orchestrator)

*Tạo file: `src/modules/employee/application/use-cases/onboard-employee.use-case.ts`*

```typescript
import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { ITransactionManager, Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { IUserRepository } from '@modules/user/domain/repositories/user.repository';
import { IUserRoleRepository, IRoleRepository } from '@modules/rbac/domain/repositories/rbac.repository';
import { IEmployeeRepository } from '@modules/employee/domain/repositories/employee.repository';
import { User } from '@modules/user/domain/entities/user.entity';
import { UserRole } from '@modules/rbac/domain/entities/user-role.entity';
import { PasswordUtil } from '@core/shared/utils/password.util';

@Injectable()
export class OnboardEmployeeUseCase {
    constructor(
        // 1. INJECT UNIT OF WORK (Giao dịch viên)
        @Inject(ITransactionManager) private readonly txManager: ITransactionManager,

        // 2. INJECT CÁC REPOSITORIES CỦA CÁC MODULE KHÁC NHAU
        @Inject(IUserRepository) private readonly userRepo: IUserRepository,
        @Inject(IRoleRepository) private readonly roleRepo: IRoleRepository,
        @Inject(IUserRoleRepository) private readonly userRoleRepo: IUserRoleRepository,
        @Inject(IEmployeeRepository) private readonly employeeRepo: IEmployeeRepository,
    ) {}

    async execute(dto: any, adminId: number) {
        
        // KIỂM TRA ĐIỀU KIỆN TRƯỚC KHI MỞ TRANSACTION (Validation)
        const role = await this.roleRepo.findByName('STAFF');
        if (!role) throw new BadRequestException('Lỗi hệ thống: Role STAFF không tồn tại');

        const hashedPassword = await PasswordUtil.hash('Welcome@2026');

        // =================================================================
        // 🔥 BẮT ĐẦU UNIT OF WORK (MỞ TRANSACTION)
        // Mọi thứ bên trong callback này sẽ dùng chung 1 kết nối DB (tx)
        // =================================================================
        return await this.txManager.runInTransaction(async (tx: Transaction) => {
            
            try {
                // 🛠️ BƯỚC 1: TẠO USER (Truyền 'tx' vào để Repository biết đang ở trong UoW)
                const newUser = new User({
                    username: dto.username,
                    email: dto.email,
                    hashedPassword: hashedPassword,
                    isActive: true,
                });
                const savedUser = await this.userRepo.save(newUser, tx);

                // 🛠️ BƯỚC 2: GÁN ROLE CHO USER
                const userRole = new UserRole({
                    userId: savedUser.id!,
                    roleId: role.id!,
                    assignedBy: adminId,
                    assignedAt: new Date()
                });
                await this.userRoleRepo.save(userRole, tx);

                // 🛠️ BƯỚC 3: TẠO HỒ SƠ NHÂN SỰ LIÊN KẾT VỚI USER VỪA TẠO
                // Cố tình tạo một lỗi ở đây (VD: employeeCode đã tồn tại làm DB văng lỗi)
                const savedEmployee = await this.employeeRepo.save({
                    userId: savedUser.id,
                    employeeCode: dto.employeeCode,
                    fullName: dto.fullName,
                    positionId: dto.positionId,
                }, tx);

                // Nếu mọi thứ trót lọt, tự động COMMIT
                return {
                    success: true,
                    user: savedUser,
                    employee: savedEmployee
                };

            } catch (error) {
                // 🚨 NẾU CÓ LỖI XẢY RA Ở BẤT KỲ BƯỚC NÀO (Kể cả bước 3)
                // Hệ thống sẽ ném lỗi ra ngoài. DrizzleTransactionManager sẽ "BẮT" được lỗi này
                // VÀ TỰ ĐỘNG ROLLBACK TOÀN BỘ (User ở Bước 1 và Role ở Bước 2 SẼ BỊ XÓA KHỎI DB)
                throw error; // Ném tiếp ra ngoài để Exception Filter xử lý trả về HTTP 400/500
            }
            
        });
        // =================================================================
        // 🛑 KẾT THÚC UNIT OF WORK
        // =================================================================
    }
}
```

---

### 4. NGUYÊN TẮC VÀNG KHI VIẾT USE CASE KẾT HỢP UoW

Để kiến trúc của bạn thực sự "Hoàn hảo và Chuyên nghiệp", hãy tuân thủ 4 quy tắc sau:

1. **Use Case chỉ đóng vai trò "Nhạc trưởng" (Orchestrator):** 
   Nó không được chứa logic if/else tính toán phức tạp (như công thức tính lương, tính giá tiền). Logic nghiệp vụ lõi (Core Business Logic) phải nằm ở `Domain Entity` (như file `user.entity.ts` của bạn) hoặc `Domain Service`. Use Case chỉ làm nhiệm vụ: Lấy Dữ liệu ➡️ Gọi Entity xử lý ➡️ Lưu Dữ liệu.
   
2. **Luôn truyền `tx` xuống TẤT CẢ các Repository bên trong UoW:**
   Nếu ở BƯỚC 2 bạn viết `await this.userRoleRepo.save(userRole);` (Quên truyền `tx`), thì bước 2 sẽ chạy ở một luồng DB độc lập. Nếu bước 3 lỗi, bước 1 bị Rollback, nhưng bước 2 vẫn bị lưu vào DB ➡️ Rác dữ liệu.

3. **Validation đọc (GET) nên để NGOÀI Transaction nếu có thể:**
   Transaction sẽ khóa table (Lock) và tốn tài nguyên DB. Những tác vụ như "Kiểm tra Role có tồn tại không" nên chạy ở ngoài `txManager.runInTransaction` để tối ưu hiệu suất (như ví dụ code trên).

4. **Event Bus (Publish Event) PHẢI ĐẶT SAU HOẶC CUỐI UoW:**
   Nếu bạn muốn gửi Email (thông qua `EventBus.publish(new UserCreatedEvent())`), hãy **đặt nó ở ngoài/hoặc cuối cùng** của Transaction. 
   Lý do: Nếu bạn gửi Email ở Bước 1, nhưng Bước 3 lỗi (Rollback). User bị xóa khỏi DB, nhưng Email thì **đã lỡ gửi đi mất rồi**!

   *Cách xử lý chuẩn:*
   ```typescript
   // Khai báo mảng chứa Event
   const eventsToPublish = [];

   await this.txManager.runInTransaction(async (tx) => {
       const user = await this.userRepo.save(newUser, tx);
       // Không publish ngay, chỉ đưa vào hàng đợi
       eventsToPublish.push(new UserCreatedEvent(user.id, { user })); 
   });

   // Chỉ khi Transaction COMMIT thành công, mới bắn Event
   for(const event of eventsToPublish) {
       await this.eventBus.publish(event);
   }
   ```

### 5. TỔNG KẾT
Việc phân tách rõ ràng:
- **Controller:** Bắt Request, Check Quyền.
- **Use Case:** Mở Unit of Work (Transaction), Điều phối các Module.
- **Domain Service/Entity:** Xử lý nghiệp vụ lõi.
- **Repository:** Chỉ giao tiếp với DB, có nhận `tx`.

Đây chính là mô hình **CQRS (Command Query Responsibility Segregation) kết hợp Clean Architecture**. Giữ vững cấu trúc này, dù dự án của bạn có scale lên 100 modules hay chia tách thành Microservices, code vẫn sẽ cực kỳ dễ bảo trì và không bao giờ bị rác dữ liệu.
