# 📐 KIẾN TRÚC VÀ NGỮ CẢNH HỆ THỐNG (BACKEND_CONTEXT)

**Triết lý cốt lõi:** Hệ thống áp dụng mô hình *Ports and Adapters (Hexagonal Architecture) + Clean Architecture + Event-Driven + UoW (ALS)*. Tuy nhiên, mức độ phức tạp bên trong mỗi Module sẽ linh hoạt thay đổi (Tiers of Complexity) phụ thuộc vào yêu cầu nghiệp vụ. Không có sự cứng nhắc "One-size-fits-all".

## 1. TECH STACK & BẢN ĐỒ THƯ MỤC
- **Tech Stack:** NestJS, Drizzle ORM (PostgreSQL), Kafka/RabbitMQ/In-Memory (Event Bus), Winston (Logger).
- **Aliases:**
  - `@core/`: Shared logic, ports, base infrastructure, UoW.
  - `@modules/<name>/`: Domain-driven modules (User, RBAC, Accounting, CRM...).
  - `@database/`: Schema định nghĩa bằng Drizzle.

## 2. PHÂN LOẠI MỨC ĐỘ PHỨC TẠP (MODULE TIERS)

### 🟢 Tier 1: Cấp độ Cơ bản (Data-Driven / Simple CRUD)
* **Đặc điểm:** Các module danh mục, từ điển, lưu log. Thêm/Đọc/Sửa/Xóa đơn thuần.
* **Quy tắc:** Không cần Domain Entities phức tạp. Trả về trực tiếp Type/Interface hoặc DTO từ Repository lên Service.
* **Ví dụ:** `NotificationModule`, `TestModule`.

### 🟡 Tier 2: Cấp độ Trung bình (Standard Business)
* **Đặc điểm:** Logic kiểm tra (Validation), xử lý quan hệ (Relations), trạng thái dữ liệu (State) không thay đổi quá phức tạp.
* **Quy tắc:**
  * Bắt buộc có `Interface Repository` (Port).
  * **Bắt buộc có `Mapper`** để tách biệt DB Schema và Application Logic.
  * Được phép dùng Anemic Model (Entity chỉ chứa Data, không chứa hàm nghiệp vụ).
* **Ví dụ:** `OrgStructureModule`, `EmployeeModule`.

### 🔴 Tier 3: Cấp độ Phức tạp (Domain-Driven / Core Business)
* **Đặc điểm:** Module cốt lõi. Yêu cầu nghiệp vụ khắt khe, thay đổi trạng thái liên tục, phát Event cho module khác.
* **Quy tắc (Bắt buộc tuân thủ DDD):**
  * **Rich Domain Entity:** Thuộc tính phải `private`, thay đổi trạng thái qua các hàm của class (vd: `user.deactivate()`, `lead.closeAsWon()`).
  * **Strict Mappers:** Chuyển đổi khắt khe giữa DB Record <-> Domain Entity.
  * **Event Driven:** Sử dụng `IEventBus` để Choreography.

---

## 3. TRÁCH NHIỆM CÁC TẦNG (LAYER RESPONSIBILITY)

1. **Domain Layer:** Chứa Entity, Value Object (VO) và Interface Repository. Tuyệt đối không phụ thuộc thư viện ngoài.
2. **Application Layer (Service):** Điều phối flow, gọi Repo qua Interface. Trigger Domain Events. **Rich Entity, Thin Service** (Logic chuyển đổi trạng thái nằm ở Entity, Service chỉ điều phối).
3. **Infrastructure Layer:** Triển khai Repository, Mappers, Adapters. Mọi kết quả DB Query phải chạy qua Mapper trước khi trả lên Service.
4. **Interface Layer (Controller):** Là ranh giới ngoài cùng. Nhận Request $\rightarrow$ Validate DTO $\rightarrow$ Gọi Service $\rightarrow$ Lấy Entity $\rightarrow$ Map sang ResponseDTO $\rightarrow$ Trả về Client.

---

## 4. QUY TẮC BẤT DI BẤT DỊCH & CHỐNG CODE SMELL (CHO AI / LLM)

Khi AI (LLM) hoặc Dev sinh code, **BẮT BUỘC** rà soát và tuân thủ các quy tắc sau:

### A. Không rò rỉ hạ tầng (Infrastructure Leakage)
* **Cấm:** Truyền biến `db` (Drizzle) hoặc Inject `@Inject(DRIZZLE)` vào Service, Factory, Strategy, Listener.
* **Bắt buộc:** Mọi giao tiếp DB phải qua Interface Repository. Binding Implementation được cấu hình tại `*.module.ts`. Controller cấm dùng object của Drizzle (`eq`, `desc`).

### B. Không rò rỉ giao diện (Presentation Leakage)
* **Cấm:** Import thư viện API (ví dụ: `ApiProperty` của Swagger, các class `...ResponseDto`) vào tầng Application Service. Hàm trong Service cấm trả về DTO hoặc `user.toJSON()`.
* **Bắt buộc:** Service chỉ trả về `Domain Entity`. Controller nhận Entity này và map sang DTO thông qua hàm tĩnh (VD: `UserResponseDto.fromDomain(entity)`).

### C. Quản lý Transaction tập trung bằng ALS
* **Cấm:** Không truyền tham số `tx` hoặc `transaction` vào bất kỳ Interface/Port nào của hệ thống.
* **Bắt buộc:** Dùng `ITransactionManager.runInTransaction(...)` tại Service. Tầng Infrastructure tự lấy transaction qua `TransactionContextService.getTx()`.

### D. Quy trình luồng dữ liệu (Strict Data Flow)
* **Cấm:** Truyền một object thô (Raw object / `{}`) vào hàm của Repository, hoặc Service trả về kết quả raw của DB (`.returning()`).
* **Luồng Đọc:** `DB Record` $\rightarrow$ `Mapper.toDomain` $\rightarrow$ `Entity` $\rightarrow$ `Service` $\rightarrow$ `Controller` $\rightarrow$ `ResponseDto.fromDomain()`.
* **Luồng Ghi:** `Controller` $\rightarrow$ `Service` $\rightarrow$ Khởi tạo `new Entity()` $\rightarrow$ `Repo.save(entity)` $\rightarrow$ `Mapper.toPersistence` $\rightarrow$ `DB Update`.

### E. Giao tiếp chéo và NestJS DI (Cross-Module Communication)
* **Cho phép:** Module A Inject Repository Interface của Module B để **đọc** dữ liệu. (Đảm bảo Module B đã `export` Repo, Module A đã `import` Module B. Cấm `provide` lại Repo của module khác).
* **Bắt buộc cho việc Ghi (Writing):**
    - **SYNC (Orchestration):** Dùng khi Module A cần kết quả trả về (VD: ID) hoặc cần đảm bảo tính toàn vẹn (Transactional Integrity). Module A phải Inject `Domain Port (Service Interface)` của Module B, thay vì Inject Repository.
    - **ASYNC (Choreography):** Dùng cho Side-effects (Gửi mail, Notify). Module A bắn Event qua `IEventBus`. Module B tự lắng nghe và xử lý.

### F. Phân loại nhiệm vụ (Task Classification & Patterns)
* **Nhiệm vụ Nhẹ/Trọng yếu (Critical/Core):** Thao tác DB liên đới cần Atomic (All-or-nothing). -> Thực hiện **SYNC** trong cùng một Transaction (sử dụng Port Call).
* **Nhiệm vụ Nặng/Phụ trợ (Heavy/Side-effect):** Gửi mail, xử lý file, tích hợp API ngoài. -> Thực hiện **ASYNC** qua EventBus để tối ưu tốc độ phản hồi.

---

## 5. TỔNG QUAN BẢN ĐỒ DỰ ÁN (PROJECT ROADMAP)

| Tên Module | Tier | Vai trò chính | Đặc điểm kỹ thuật đáng chú ý |
| :--- | :---: | :--- | :--- |
| **Shared/Core** | N/A | Abstraction Layer | Chứa `TransactionManager`, `EventBus Adapter`, `HttpFilters`, `Logger`. |
| **Auth** | Tier 3 | Xác thực & JWT | Quản lý Session bằng PostgreSQL + Redis Caching. Cấp phát JWT. |
| **User** | Tier 3 | Identity (Định danh) | Rich Domain Model. Hàm logic nằm gọn trong `User Entity`. |
| **RBAC** | Tier 3 | Quản lý Phân quyền | Phân quyền động, lưu cache permission trên Redis tối ưu Guard. |
| **Accounting** | Tier 3 | Kế toán (Thu/Chi) | Kiến trúc 4 lớp (Header-Items-Cash-Mapping). Công cụ đối soát tài chính chuyên nghiệp. |
| **CRM** | Tier 3 | Quản lý Khách hàng | Quản lý vòng đời Lead $\rightarrow$ Organization $\rightarrow$ Contract bằng Events. |
| **OrgStructure**| Tier 2 | Tổ chức & Định biên | Thuật toán vẽ sơ đồ cây phân cấp (Tree Hierarchy). |
| **Employee** | Tier 2 | Hồ sơ nhân viên | Cấp tài khoản (Provision) sau khi Onboard qua Event-Driven. |
| **Notification**| Tier 1 | Thông báo hệ thống | Bắt sự kiện bất đồng bộ qua `EventBus` gửi Email/Telegram. |

> **📝 Châm ngôn của Team Backend:** 
> *"Kiến trúc không phải là đích đến, kiến trúc là công cụ để giải quyết bài toán kinh doanh. Nếu tính năng đó chỉ cần 2 tiếng để viết CRUD, đừng tốn 2 ngày để thiết kế DDD. Nếu tính năng đó là lõi sinh tiền của công ty, hãy viết nó chặt chẽ như một pháo đài."*
