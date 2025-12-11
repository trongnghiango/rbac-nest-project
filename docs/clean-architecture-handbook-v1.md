Đây là phiên bản hoàn thiện của **"Clean Architecture Handbook for Backend Engineers"**.

Tôi đã cụ thể hóa từng giai đoạn bằng **Code (TypeScript/NestJS style)** cho cùng một bài toán: **"Đăng ký thành viên mới (User Registration)"**. Điều này giúp bạn so sánh trực quan sự thay đổi của dòng code khi tư duy kiến trúc thay đổi.

---

# 📘 CLEAN ARCHITECTURE HANDBOOK (Phiên bản Thực chiến)

**Bài toán mẫu:** User đăng ký tài khoản.
**Yêu cầu:**
1. Kiểm tra email tồn tại chưa.
2. Mã hóa password.
3. Lưu vào DB.
4. Gửi email chào mừng.

---

## 🛑 Stage 0 — "Spaghetti Code" (Service cái gì cũng nhét vào)

Đây là code điển hình của người mới học hoặc dự án prototype làm trong 1 đêm.

### Code
```typescript
// user.service.ts
@Injectable()
class UserService {
  // Tiêm trực tiếp ORM Entity
  constructor(@InjectRepository(UserEntity) private userRepo: Repository<UserEntity>) {}

  async register(req: any, res: any) { // ❌ Nhận cả Request/Response object
    const { email, password } = req.body;
    
    // ❌ Logic validate nằm lộn xộn
    if (password.length < 6) return res.status(400).json({ msg: 'Pass weak' });

    // ❌ Logic DB nằm cứng trong service
    const existing = await this.userRepo.findOne({ where: { email } });
    if (existing) throw new Error('User exists');

    // ❌ Logic mã hóa (Infrastructure) trộn lẫn
    const hashedPassword = bcrypt.hashSync(password, 10);

    const user = this.userRepo.create({ email, password: hashedPassword });
    await this.userRepo.save(user);

    // ❌ Logic gửi mail (3rd party) nằm cứng ở đây
    await sendMail(email, 'Welcome!'); 

    return res.json(user);
  }
}
```

### Đánh giá
*   **Ưu điểm:** Viết siêu nhanh.
*   **Nhược điểm:**
    *   Không thể Unit Test (vì phụ thuộc `req`, `res`, `db`, `mail` thật).
    *   Thay đổi thư viện mail/DB là phải sửa code Service.
    *   Không tái sử dụng được (nếu muốn đăng ký user từ file CSV import thì chịu).

---

## 🚧 Stage 1 — Service + Repository (Mức Startup phổ biến)

Tách biệt việc truy xuất dữ liệu (DB) ra khỏi logic xử lý.

### Code
```typescript
// user.service.ts
@Injectable()
class UserService {
  constructor(
    private userRepo: UserRepository, // ✅ Đã tách repo riêng
    private mailService: MailService  // ✅ Đã tách mail service
  ) {}

  async register(dto: CreateUserDto) { // ✅ Dùng DTO, không dùng req/res
    const existing = await this.userRepo.findByEmail(dto.email);
    if (existing) throw new Error('User exists');

    // ⚠️ Vẫn còn logic business ở Service
    if (dto.password.length < 6) throw new Error('Pass weak');
    
    const hashedPassword = await bcrypt.hash(dto.password, 10);
    
    const user = await this.userRepo.create({ ...dto, password: hashedPassword });
    
    await this.mailService.sendWelcome(user.email); // ⚠️ Side effect vẫn ở đây
    return user;
  }
}
```

### Đánh giá
*   **Ưu điểm:** Code gọn hơn, DB query tái sử dụng được.
*   **Nhược điểm:**
    *   **Service Fat:** Service chứa cả logic nghiệp vụ (check pass) lẫn logic điều phối (gọi mail).
    *   **Anemic Model:** Entity User chỉ là cái khung chứa dữ liệu (Getters/Setters), không có hồn.

---

## ❌ Stage 2 — UseCase = Service (Sai lầm phổ biến nhất)

Nhiều team áp dụng Clean Arch nhưng chỉ đổi tên `Service` thành `UseCase`.

### Code
```typescript
// register-user.usecase.ts
export class RegisterUserUseCase {
  constructor(private userRepo: UserRepository) {}

  async execute(dto: CreateUserDto) {
    // ❌ Y hệt logic bên Service Stage 1 copy sang
    if (dto.password.length < 6) throw new Error('Pass weak');
    // ... code cũ ...
  }
}
```
### Đánh giá
*   **Vấn đề:** Không mang lại giá trị gì ngoài việc thêm file. Logic nghiệp vụ vẫn không được bảo vệ trong Domain.

---

## 💎 Stage 3 & 4 — Clean Architecture + Rich Domain Model

Đây là bước chuyển mình quan trọng nhất. Logic nghiệp vụ phải chui vào **Entity**.

### 1. Domain Layer (Trái tim của hệ thống)
```typescript
// core/domain/user.entity.ts
export class User {
  // ✅ Private constructor để ép dùng factory method
  private constructor(
    public readonly id: string,
    public readonly email: string,
    private _password: string // Private để không bị set bậy bạ
  ) {}

  // ✅ Factory method: Chứa logic tạo mới
  static create(email: string, plainPass: string): User {
    if (plainPass.length < 6) throw new DomainError('Password too weak'); // Business Logic
    // Lưu ý: Việc hash pass có thể nằm ở Domain Service nếu coi là logic nghiệp vụ
    return new User(uuid(), email, plainPass); 
  }
}
```

### 2. Application Layer (UseCase - Chỉ là người điều phối)
```typescript
// core/application/use-cases/register-user.usecase.ts
export class RegisterUserUseCase {
  constructor(
    // ✅ Dependency Inversion: Chỉ phụ thuộc vào Interface (Port)
    private readonly userRepo: IUserRepository, 
    private readonly hasher: IPasswordHasher
  ) {}

  async execute(command: RegisterUserCommand): Promise<void> {
    // 1. Kiểm tra logic nghiệp vụ tầng App (nếu có)
    const existing = await this.userRepo.findByEmail(command.email);
    if (existing) throw new ConflictError('User exists');

    // 2. Gọi Domain để thực thi Business Logic
    const hashedPassword = await this.hasher.hash(command.password);
    const user = User.create(command.email, hashedPassword);

    // 3. Persistence
    await this.userRepo.save(user);
    
    // Lưu ý: Chưa gửi mail ở đây để tránh side-effect làm chậm request
  }
}
```

### Đánh giá
*   **Ưu điểm:**
    *   `User.create` đảm bảo một User được tạo ra **luôn luôn đúng** (valid state).
    *   UseCase rất sạch, chỉ đọc như văn xuôi.
    *   Repo là Interface, implementation (TypeORM/Mongo) nằm ở Infra -> Dễ đổi DB.

---

## 🚀 Stage 5 — DDD + Event-Driven (Enterprise Level)

Giải quyết vấn đề: Đăng ký xong thì gửi mail, bắn noti, tính điểm thưởng... mà không làm UseCase phình to.

### 1. Domain Events
```typescript
// core/domain/user.entity.ts
export class User extends AggregateRoot { // Kế thừa AggregateRoot để quản lý event
  static create(email: string, pass: string): User {
    const user = new User(uuid(), email, pass);
    // ✅ User tự hét lên: "Tao vừa được tạo nè!"
    user.addDomainEvent(new UserRegisteredEvent(user.id, user.email));
    return user;
  }
}
```

### 2. UseCase (Vẫn sạch sẽ)
```typescript
// register-user.usecase.ts
async execute(command: RegisterUserCommand) {
  const user = User.create(command.email, ...);
  await this.userRepo.save(user); 
  // ⚠️ Repository implementation sẽ tự động dispatch events khi save thành công
}
```

### 3. Event Handler (Xử lý tác vụ phụ)
```typescript
// core/application/handlers/send-welcome-email.handler.ts
@EventsHandler(UserRegisteredEvent)
export class SendWelcomeEmailHandler implements IEventHandler<UserRegisteredEvent> {
  constructor(private mailer: IMailerAdapter) {}

  async handle(event: UserRegisteredEvent) {
    // ✅ Logic gửi mail nằm hoàn toàn tách biệt
    await this.mailer.send(event.email, 'Welcome content...');
  }
}
```

### Đánh giá
*   **Ưu điểm:**
    *   **Decoupling:** UseCase không biết Mailer tồn tại. Nếu mai sau cần thêm "Tặng coupon khi đăng ký", chỉ cần viết thêm 1 Handler mới, không sửa code cũ (Open-Closed Principle).
    *   **Performance:** Có thể đẩy Event vào Message Queue (RabbitMQ/Kafka) để xử lý bất đồng bộ.

---

## 🏆 Final Stage — Bảng tổng hợp các thành phần

Dưới đây là cấu trúc folder và nhiệm vụ chuẩn để bạn tra cứu:

| Layer | Component | Ví dụ (Naming Convention) | Nhiệm vụ chính | Quy tắc bất di bất dịch |
| :--- | :--- | :--- | :--- | :--- |
| **Domain** | Entity | `User`, `Order` | Chứa logic nghiệp vụ cốt lõi, State validation. | Không phụ thuộc framework, DB, libs ngoài. |
| | Value Object | `Email`, `Address`, `Money` | Chứa logic của thuộc tính (vd: format email). | Immutable (Bất biến). |
| | Domain Event | `UserRegisteredEvent` | Thông báo sự thay đổi trạng thái. | Chỉ chứa data nguyên thủy. |
| **Application** | UseCase | `RegisterUserUseCase` | Orchestrator: Gọi Domain, gọi Repo. | Không chứa `if/else` nghiệp vụ phức tạp. |
| | Port (Interface) | `IUserRepository`, `IMailer` | Định nghĩa input/output cho Infra. | Giúp đảo ngược sự phụ thuộc (DIP). |
| | Command/Query | `CreateUserCommand` | DTO input cho UseCase. | Tách biệt Write (Command) và Read (Query). |
| **Infrastructure** | Adapter | `TypeOrmUserRepository` | Thực thi interface của App layer. | Là nơi duy nhất biết DB/Lib 3rd party là gì. |
| | DTO (Infra) | `UserSchema`, `UserEntityDB` | Mapping với Database Table. | Không được lọt vào Domain layer. |
| **Presentation** | Controller | `UserController` | Nhận HTTP request, gọi UseCase. | Chỉ làm nhiệm vụ parse request & response. |

---

## ⚠️ Mục Lưu ý quan trọng (Dành cho Senior)

Khi áp dụng mô hình Final Stage, bạn sẽ gặp 3 vấn đề lớn sau, cần có giải pháp:

### 1. Vấn đề Transaction (Unit of Work)
*   **Vấn đề:** UseCase gọi `userRepo.save()` rồi gọi `walletRepo.save()`. Nếu cái sau chết, cái đầu đã lỡ lưu vào DB.
*   **Giải pháp:** Dùng pattern **UnitOfWork** hoặc **Transactional Decorator** ở tầng Application.
    ```typescript
    @Transactional() // Đảm bảo toàn bộ function chạy trong 1 transaction
    async execute(command: ...) { ... }
    ```

### 2. Vấn đề Mapping (Mapper Overhead)
*   **Vấn đề:** Data chạy từ `DB Entity -> Domain Entity -> DTO Response` tốn tài nguyên.
*   **Giải pháp (CQRS):**
    *   **Write side (Command):** Bắt buộc map qua Domain Entity để đảm bảo logic.
    *   **Read side (Query):** Cho phép UseCase (QueryHandler) gọi thẳng Repo đọc Raw SQL/DB View trả về DTO luôn. **Bypass Domain Layer** để tối ưu tốc độ đọc.

### 3. Vấn đề "Over-engineering"
*   **Lời khuyên:** Đừng áp dụng Stage 5 cho CRUD đơn giản (ví dụ bảng danh mục, setting). Hãy dùng Stage 1 cho những module đơn giản, và Stage 5 cho Core Business (Order, Payment). Một dự án có thể tồn tại song song nhiều kiến trúc (Modular Monolith).

---

Tài liệu này được biên soạn để làm kim chỉ nam. Khi review code của team, hãy soi chiếu xem module đó đang ở Stage nào và liệu nó có cần nâng cấp hay hạ cấp không.