# BACKEND_CONTEXT.md

**Kiến trúc:** Clean Architecture + DDD + Event-Driven + Ports/Adapters (Hexagonal) + UoW (Drizzle + AsyncLocalStorage) + DI (NestJS).

## 1. Bản đồ Thư mục & Aliases
- `@core/`: Shared logic, ports, base infrastructure.
- `@modules/<name>/`: Domain-driven modules (User, RBAC, Accounting, CRM, v.v.).
- Thư mục Module: `domain/` (Entity, VO, Repo Interface), `application/` (Services/UseCases, DTOs), `infrastructure/` (Repo Impl, Mappers, Controllers).
- `@database/`: Schema định nghĩa bằng Drizzle.

## 2. Quy tắc QA & Implement (BẮT BUỘC)

### A. Layer Responsibility
1. **Domain Layer:** 
   - Tuyệt đối không phụ thuộc vào thư viện bên ngoài (trừ VO đơn giản).
   - Logic nghiệp vụ chính nằm trong Entity hoặc Domain Service.
   - **Repository Interface** nằm ở đây.
2. **Application Layer:**
   - Điều phối flow, gọi Repository qua Interface.
   - Sử dụng `ITransactionManager.runInTransaction` cho các thao tác ghi.
   - Trigger **Domain Events** sau khi commit thành công.
3. **Infrastructure Layer:**
   - Triển khai Repository, Mappers, Adapters (PDF, File Storage).
   - **Mappers:** Luôn chuyển đổi DB Record <-> Domain Entity qua Mapper class. Không trả về raw DB object cho App layer.
4. **Interface Layer (API):**
   - Controllers chỉ nhận/validate DTO và gọi Application Service.
   - Sử dụng `@CurrentUser()` decorator.

### B. Transaction & Unit of Work (ALS)
- Hệ thống dùng `AsyncLocalStorage` (ALS) để quản lý Transaction ngầm định.
- **QUY TẮC CỨNG:** 
    1. **Cấm** tham số `tx` hoặc `transaction` trong bất kỳ Interface/Port nào.
    2. Tầng Infrastructure (Repository Impl) tự lấy transaction qua `TransactionContextService.getTx()`.
    3. Tầng Application **tuyệt đối không** truyền transaction vào Repository.

## 3. Quy tắc trả lời của LLM (BỔ SUNG)
1. **Rà soát Dependency Injection (DI):** Trước khi cung cấp code, phải tự kiểm tra:
   - Các Repository/Service mới đã được `provide` trong Module chưa?
   - Nếu dùng Repo từ module khác, Module đó đã `export` Repo đó chưa? Module hiện tại đã `import` Module đó chưa?
2. **Refactor triệt để:** Khi được yêu cầu xóa rò rỉ hạ tầng (ví dụ: xóa `DRIZZLE`), phải truy vết toàn bộ: Service -> Factory -> Strategy -> Repo. Cấm để lại tham số "mồ côi" dẫn đến lỗi logic.
3. **Show code:** Sửa ít dùng diff, sửa nhiều/file mới dùng full code. Luôn kèm theo cấu hình Module nếu có thêm Dependency.

## 4. QUY TẮC CHỐNG CODE SMELL (ANTI-PATTERNS)

### A. Tuyệt đối không rò rỉ hạ tầng (Infrastructure Leakage)
- **Sai:** Inject `DRIZZLE` hoặc truyền biến `db` vào Service, Listener, Factory, hay Strategy.
- **Đúng:** Mọi thứ phải đi qua Repository Interface. Nếu Strategy cần data, hãy inject Repository vào Strategy đó.

### B. Liên lạc giữa các Module (Cross-Module Communication)
- **Ưu tiên Choreography (Event-Driven):** Để tránh `forwardRef` và Circular Dependency, Module A bắn Event, Module B nghe và tự xử lý data của chính nó.
- **Quy tắc sở hữu:** Module nào quản lý bảng đó thì chỉ Module đó mới có quyền gọi Repository để `save/update` bảng đó. Các module khác muốn tác động phải bắn Event.

### C. Quy trình trả về dữ liệu (Data Flow)
- **BẮT BUỘC:** `DB Record` -> `Mapper.toDomain` -> `Entity` -> `Service`. 
- Cấm trả về kết quả trực tiếp của Drizzle (như kết quả từ `.returning()`) ra khỏi tầng Infrastructure.

### D. Fat Entity, Thin Service
- Logic kiểm tra trạng thái, chuyển đổi trạng thái (State Transition) phải nằm trong Entity. Service chỉ điều phối.

### E. Quản lý ID & Mã định danh
- Dùng `number` (BigInt) cho quan hệ DB.
- Dùng mã nghiệp vụ (`code`, `username`, `employeeCode`) trong Events để tăng tính độc lập giữa các module.

## 5. NestJS Module Management
- Khi một Module (ví dụ: `Accounting`) cần data từ Module khác (ví dụ: `Crm`):
    1. Module `Crm` phải `export` Repository Interface.
    2. Module `Accounting` phải `import` `CrmModule`.
    3. Tuyệt đối không `provide` lại Repository của Module khác trong Module hiện tại.

## 6. Tech Stack Context
- Framework: NestJS. ORM: Drizzle (PostgreSQL). 
- Event Bus: Kafka/RabbitMQ/In-Memory.
- Logger: Winston (Port/Adapter).
- Static Files: `/models` hoặc `/uploads`.
