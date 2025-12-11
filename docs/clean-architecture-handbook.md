# Clean Architecture Handbook for Backend Engineers

---

## 📘 Mục Lục

1. Giới thiệu
2. Tư duy nền tảng
3. Stage 0 — Code dạng “Service cái gì cũng nhét vào”
4. Stage 1 — Service + Repository (mức startup phổ biến)
5. Stage 2 — UseCase = Service (sai lầm phổ biến nhất)
6. Stage 3 — Clean Architecture sơ cấp
7. Stage 4 — Clean + Hexagonal Architecture
8. Stage 5 — DDD + Event-driven + Anti-corruption Layer
9. Final Stage — Clean Architecture hoàn chỉnh nhất
10. Tổng hợp lỗi thường gặp và cách sửa
11. Kết luận

---

## 1. Giới thiệu

Tài liệu này mô tả hành trình tiến hóa kiến trúc backend từ mô hình đơn giản, thiếu ràng buộc đến Clean Architecture hoàn chỉnh — áp dụng cho **NestJS + TypeORM**, nhưng tư duy hoàn toàn độc lập framework.

Bạn sẽ học:

* Cách kiến trúc thực sự phát triển khi scale.
* Tại sao nhiều dự án "trông có vẻ clean" nhưng sai hoàn toàn.
* Vì sao UseCase không phải Service và ngược lại.
* Cách phân chia đúng 4 lớp: Domain – Application – Infrastructure – Interface.
* Template chuẩn cho backend ở cấp độ enterprise.

---

## 2. Tư duy nền tảng

Kiến trúc sạch bắt đầu từ 3 nguyên lý cốt lõi:

### **2.1. Dependency Rule**

> *Code ở vòng trong không bao giờ phụ thuộc vào vòng ngoài.*

### **2.2. Separation of Concerns**

* Domain = sự thật nghiệp vụ.
* Application = orchestrator.
* Infrastructure = implementation.
* Interface/Delivery = REST/GraphQL/CLI.

### **2.3. Enterprise Boundary**

Đừng để framework, database, transport chi phối domain.

---

## 3. Stage 0 — “Service như cái thùng rác”

### 3.1. Biểu hiện

* UserService chứa hết mọi thứ.
* Không repo, không domain, không layer.

### 3.2. Vấn đề

* Không test được.
* Logic lẫn external IO.
* Không mở rộng.

### 3.3. Cách nâng cấp

* Tách repository.
* Tách external adapter.
* Bắt đầu dùng interface.

---

## 4. Stage 1 — “Service + Repository”

### 4.1. Biểu hiện

* Có IUserRepository.
* Có UserService.
* Controller → Service → Repo.

### 4.2. Vấn đề

* Service chứa luôn domain logic.
* Domain chưa tách biệt.

### 4.3. Nâng cấp

* Thêm Domain Service.
* Chuẩn bị đưa UseCase vào.

---

## 5. Stage 2 — “UseCase = Service” (Sai lầm phổ biến nhất)

### 5.1. Biểu hiện

* UseCase implement interface Service.
* UseCase chứa domain logic.

### 5.2. Tại sao sai?

* UseCase là *application flow*, không phải domain logic.
* Domain logic phải nằm ở Domain Service.

### 5.3. Cách sửa

* Tách Application UseCase và Domain Service.
* UseCase chỉ orchestration & delegation.

---

## 6. Stage 3 — Clean Architecture sơ cấp

### 6.1. Cấu trúc

```
core/
  domain/
  usecases/
infra/
  repositories/
modules/
  users/
```

### 6.2. Ưu điểm

* Domain bắt đầu thuần.
* Flow rõ hơn.

### 6.3. Lỗi còn gặp

* DTO rối.
* Mapper chưa có.
* Domain chưa có VO (value object).

---

## 7. Stage 4 — Clean + Hexagonal Architecture

### 7.1. Chuẩn hoá ports/adapters

```
application → ports (interfaces)
infrastructure → adapters (implementations)
```

### 7.2. UseCase chuẩn

* Không chứa logic.
* Chỉ gọi domain service + repo.

### 7.3. Domain sạch 100%

* Entities
* Value Objects
* Domain Service
* Domain Events

---

## 8. Stage 5 — DDD + Event-driven + ACL

### 8.1. Thêm domain events

* Tách việc “publish event” khỏi UseCase.
* UseCase không gọi mailer trực tiếp.

### 8.2. Event Handler

* Application layer nhận event, xử lý external.

### 8.3. Anti-corruption Layer (ACL)

* Giải quyết khi tích hợp hệ thống legacy.

### 8.4. Context Mapping

* Khi hệ thống có nhiều bounded contexts.

---

## 9. Final Stage — Kiến trúc chuẩn Enterprise

### 9.1. Cấu trúc hoàn chỉnh

```
/core
  /domain
    entities
    aggregates
    value-objects
    domain-services
    domain-events
  /application
    commands
    queries
    mappers
    ports
/infra
  database
  cache
  event-bus
  mailer
  auth
/modules (delivery)
  rest
  graphql
  cli
```

### 9.2. Luồng chạy tiêu chuẩn

Controller → CommandBus → UseCase → Domain → Repo → Domain Events → EventBus → Handler

### 9.3. Lợi ích tối đa

* Testable 100%.
* Không phụ thuộc DB/framework.
* Dễ scale sang microservices.
* Dễ thay UI (REST → GraphQL).

---

## 10. Tổng hợp lỗi thường gặp theo từng stage

| Stage | Lỗi                    | Nguyên nhân         | Giải pháp                |
| ----- | ---------------------- | ------------------- | ------------------------ |
| 0     | God Service            | Không biết boundary | Tách repo, adapter       |
| 1     | Business trong Service | Service = domain?   | Domain Service           |
| 2     | UseCase = Service      | Nhầm vai            | UseCase orchestration    |
| 3     | DTO lộn xộn            | Thiếu mapper        | Thêm mapping layer       |
| 4     | Domain import infra    | Phá dependency rule | Port/adapter đúng        |
| 5     | Flow rối               | Sync flow           | Event-driven             |
| Final | Code phức tạp          | Không CQRS          | Query/Command separation |

---

## 11. Kết luận

Kiến trúc sạch không phải là file structure đẹp mắt — nó là **tư duy boundary**.

Một hệ thống sạch:

* Domain không biết DB là gì.
* App không biết TypeORM là gì.
* Repo không biết controller là gì.
* Framework có thể thay đổi mà domain vẫn sống tiếp.

Nếu bạn nắm toàn bộ stages trong tài liệu này, bạn có thể tự tin xây hệ thống theo chuẩn enterprise.

---

**Bạn muốn chương tiếp theo là gì?**

* Thêm *template code* hoàn chỉnh?
* Thêm phiên bản *PDF export*?
* Thêm *use-case real-world* (Order, Payment, Booking, Inventory)?

