# 📐 QUY CHUẨN KIẾN TRÚC THÍCH ỨNG (ADAPTIVE ARCHITECTURE)

**Triết lý cốt lõi:** Hệ thống áp dụng mô hình *Ports and Adapters (Hexagonal Architecture)* làm khung xương chính để tách biệt Logic và Framework. Tuy nhiên, **Mức độ phức tạp bên trong mỗi Module sẽ linh hoạt thay đổi (Tiers of Complexity)** phụ thuộc vào yêu cầu nghiệp vụ của chính Module đó. Không có sự cứng nhắc "One-size-fits-all".

## 1. PHÂN LOẠI MỨC ĐỘ PHỨC TẠP (MODULE TIERS)

Chúng ta chia các Module trong hệ thống thành 3 cấp độ (Tiers). Lập trình viên khi nhận task cần xác định Feature này thuộc Tier nào để chọn cách code phù hợp.

### 🟢 Tier 1: Cấp độ Cơ bản (Data-Driven / Simple CRUD)
* **Đặc điểm:** Các module mang tính chất danh mục, từ điển, lưu log, hoặc chỉ đơn thuần là Thêm/Đọc/Sửa/Xóa không có logic nghiệp vụ phức tạp.
* **Quy tắc thiết kế:**
  * Bỏ qua tầng `Domain Entities` (Rich Model).
  * Bỏ qua `Mappers`.
  * Trả về trực tiếp Plain Object (Type/Interface) hoặc DTO từ Repository lên Service.
* **Module ví dụ trong dự án:** `NotificationModule`, `TestModule`.
* **Cấu trúc thư mục chuẩn (Tier 1):**
  ```text
  notification/
  ├── controllers/
  ├── services/
  ├── dtos/
  └── repositories/ (Interface + Implementation, trả về Type)
  ```

### 🟡 Tier 2: Cấp độ Trung bình (Logic-Driven / Standard Business)
* **Đặc điểm:** Các module có logic kiểm tra (Validation), xử lý quan hệ (Relations), nhưng trạng thái dữ liệu (State) không thay đổi quá phức tạp.
* **Quy tắc thiết kế:**
  * Cần có `Interface Repository` (Port) để giấu đi thư viện ORM.
  * Logic gom vào `Service`.
  * Có thể dùng `Entity` nhưng dưới dạng Anemic Model (Chỉ là Interface định nghĩa cấu trúc dữ liệu, không chứa hàm xử lý logic).
  * Không bắt buộc phải có Mapper chặt chẽ.
* **Module ví dụ trong dự án:** `OrgStructureModule`, `EmployeeModule`.
* **Cấu trúc thư mục chuẩn (Tier 2):**
  ```text
  employee/
  ├── controllers/
  ├── dtos/
  ├── services/
  └── domain/
      └── repositories/ (Interface định nghĩa IEmployeeRepository)
  └── infrastructure/
      └── persistence/ (DrizzleEmployeeRepository)
  ```

### 🔴 Tier 3: Cấp độ Phức tạp (Domain-Driven / Core Business)
* **Đặc điểm:** Các module cốt lõi của hệ thống (Core). Có nhiều quy tắc nghiệp vụ khắt khe, thay đổi trạng thái liên tục, yêu cầu bảo mật cao, hoặc cần phát Event cho các module khác.
* **Quy tắc thiết kế (Bắt buộc tuân thủ DDD):**
  * **Rich Domain Entity:** Entity phải là Class (`user.entity.ts`), các thuộc tính phải là `private`, trạng thái chỉ được thay đổi qua các hàm của class (vd: `user.deactivate()`, `user.changePassword()`).
  * **Strict Mappers:** Bắt buộc phải có `Mapper` (`UserMapper.toDomain`, `UserMapper.toPersistence`) để biến đổi data từ DB thành Domain Entity và ngược lại. Cấm rò rỉ cấu trúc DB ra ngoài Repository.
  * **Event Driven:** Sử dụng `IEventBus` để publish sự kiện khi có thay đổi quan trọng (vd: `UserCreatedEvent`).
* **Module ví dụ trong dự án:** `UserModule`, `AuthModule`, `RbacModule`.
* **Cấu trúc thư mục chuẩn (Tier 3):**
  ```text
  user/
  ├── infrastructure/
  │   ├── controllers/
  │   ├── dtos/
  │   └── persistence/
  │       ├── mappers/ (UserMapper)
  │       └── drizzle-user.repository.ts
  ├── application/
  │   └── services/ (Điều phối Domain Entity)
  └── domain/
      ├── entities/ (Rich Class: User.ts)
      ├── events/ (UserCreatedEvent)
      └── repositories/ (Interface IUserRepository)
  ```

---

## 2. QUY TẮC BẤT DI BẤT DỊCH (THE STRICT RULES)

Dù Module của bạn linh hoạt ở Tier 1, 2 hay 3, bạn **BẮT BUỘC** phải tuân thủ 4 quy tắc ranh giới (Boundaries) sau đây để hệ thống không bị "thối rữa" (Software Rot) theo thời gian:

### Quy tắc 1: Dependency Inversion (Tiêm phụ thuộc qua Interface)
* **Cấm:** Service không bao giờ được phép Import trực tiếp `DrizzleUserRepository`.
* **Bắt buộc:** Service chỉ được phép Import và Inject Interface (`IUserRepository`) sử dụng `Symbol`. Việc binding (kết nối) Interface với Implementation Drizzle được thực hiện tại file `*.module.ts`.
* *Lý do:* Để có thể viết Unit Test dễ dàng (Mocking) và đổi ORM (sang Prisma/TypeORM) mà không phải sửa 1 dòng code nào ở Service.

### Quy tắc 2: Controller mù tịt về Database
* **Cấm:** Controller không được phép biết dự án đang dùng PostgreSQL hay Drizzle. Không truyền object của Drizzle (`eq`, `desc`) từ Controller xuống.
* **Bắt buộc:** Controller chỉ làm 3 việc: Nhận Request $\rightarrow$ Validate DTO $\rightarrow$ Gọi Service $\rightarrow$ Trả Response.

### Quy tắc 3: Quản lý Transaction tập trung
* **Cấm:** Không được phép gọi `db.transaction()` trực tiếp bên trong Service.
* **Bắt buộc:** Mọi nghiệp vụ cần Transaction (ghi nhiều bảng cùng lúc) phải được bọc trong `ITransactionManager.runInTransaction(...)`. Trạng thái của Transaction (`tx`) được truyền xuống Repository dưới dạng tham số tùy chọn.
* *Lý do:* Giữ cho Service không bị ô nhiễm bởi thư viện DB.

### Quy tắc 4: Cross-Module Communication (Giao tiếp chéo)
Khi Module A cần dữ liệu của Module B:
* **Cho phép:** `EmployeeService` được phép Inject `IOrgStructureRepository` (Mượn Repository của hàng xóm để chỉ đọc dữ liệu).
* **Khuyến khích:** Sử dụng `EventBus` (Publish/Subscribe) để giao tiếp bất đồng bộ nếu hành động đó không cần kết quả ngay lập tức (Ví dụ: Tạo User xong bắn Event để NotificationModule gửi Email).

---

## 3. TỔNG QUAN BẢN ĐỒ DỰ ÁN (PROJECT ROADMAP)

Bảng dưới đây cung cấp cái nhìn tổng quan cho team về cách hệ thống đang được vận hành:

| Tên Module | Tier | Vai trò chính | Đặc điểm kỹ thuật đáng chú ý |
| :--- | :---: | :--- | :--- |
| **Shared/Core** | N/A | Cung cấp Abstraction Layer | Chứa `TransactionManager`, `EventBus Adapter`, `HttpFilters`, `Logger`. Mọi module đều import từ đây. |
| **Auth** | Tier 3 | Xác thực & Phân quyền | Quản lý Session bằng PostgreSQL + Redis (Caching 2 lớp). Cấp phát JWT. |
| **User** | Tier 3 | Identity (Định danh) | Áp dụng Rich Domain Model. Hàm xử lý logic nằm gọn trong `User Entity`. Có Mapper chặt chẽ. |
| **RBAC** | Tier 3 | Quản lý Phân quyền | Phân quyền động, lưu cache permission trên Redis (`rbac:permissions:{id}`) để tối ưu tốc độ check Guard. |
| **OrgStructure**| Tier 2 | Tổ chức & Định biên (HRM) | Thuật toán vẽ sơ đồ cây O(N) trên RAM. Tự động sinh Matrix Vị trí. (Không dùng Mapper). |
| **Employee** | Tier 2 | Hồ sơ nhân viên (HRM) | Tách biệt với User. Cấp tài khoản (Provision) sau khi Onboard. |
| **Notification**| Tier 1 | Thông báo (System) | Bắt sự kiện bất đồng bộ qua `EventBus` (UserCreated $\rightarrow$ Send Welcome Email). |

---

> **📝 Châm ngôn của Team Backend:** 
> *"Kiến trúc không phải là đích đến, kiến trúc là công cụ để giải quyết bài toán kinh doanh. Nếu tính năng đó chỉ cần 2 tiếng để viết CRUD, đừng tốn 2 ngày để thiết kế DDD. Nếu tính năng đó là lõi sinh tiền của công ty, hãy viết nó chặt chẽ như một pháo đài."*
