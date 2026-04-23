#

Dựa trên "Hiến pháp" BACKEND_CONTEXT.md vừa update  kiểm tra xem còn  "Smell" chưa  refactor cụ thể cho 6 vấn đề bên dưới không?.
### 1. Vấn đề nghiêm trọng nhất: Infrastructure Leakage (Rò rỉ hạ tầng)
Vị trí:
src/modules/accounting/application/services/finote.service.ts
src/modules/accounting/application/listeners/finote-created.listener.ts
src/modules/org-structure/application/services/company-import.service.ts
Code Smell:
Sử dụng trực tiếp @Inject(DRIZZLE) private db và các hàm query của Drizzle (this.db.insert, this.db.query.findFirst) ngay trong tầng Application Service/Listener.
Hệ quả:
Vi phạm nguyên tắc Ports/Adapters. Tầng App bị phụ thuộc cứng vào Drizzle. Không thể viết Unit Test cho Service mà không cần DB thật.
Đề xuất Refactor:
Định nghĩa IFinoteRepository trong tầng Domain.
Chuyển toàn bộ logic truy vấn vào DrizzleFinoteRepository trong tầng Infrastructure.
Service chỉ gọi this.finoteRepo.save(finote).
### 2. Vấn đề: Anemic Domain Model (Entity "thiếu máu")
Vị trí:
src/modules/crm/domain/entities/lead.entity.ts
src/modules/crm/application/services/lead-workflow.service.ts
src/modules/user/domain/entities/user.entity.ts
Code Smell:
Entity chỉ là các class chứa data (getter/setter). Logic nghiệp vụ quan trọng lại nằm ở Service.
Ví dụ trong LeadWorkflowService.closeLeadAsWon: Logic kiểm tra lead.isWon(), logic cập nhật thông tin Organization đều nằm ở Service.
Hệ quả:
Service trở nên cực kỳ phức tạp (Fat Service). Logic nghiệp vụ bị phân tán, khó tái sử dụng.
Đề xuất Refactor:
Đưa logic "Chốt Lead" vào Entity Lead: lead.closeAsWon(contractDetails).
Đưa logic "Nâng cấp khách hàng" vào Entity Organization: org.upgradeToEnterprise(taxCode, name).
Service chỉ làm nhiệm vụ lấy Org/Lead ra, gọi các hàm này và lưu lại.
### 3. Vấn đề: Thiếu Mappers & Lộ DB Model
Vị trí:
src/modules/employee/application/services/employee.service.ts (Hàm onboardNewEmployee trả về trực tiếp kết quả từ repo mà không qua mapper).
src/modules/accounting/application/services/finote.service.ts (Trả về savedFinote là kết quả insert trực tiếp của Drizzle).
Code Smell:
Dữ liệu trả ra ngoài Service là các đối tượng mang cấu trúc bảng (database schema) thay vì cấu trúc nghiệp vụ (domain entity).
Hệ quả:
Nếu bạn đổi tên cột trong DB, toàn bộ UI/Frontend sẽ bị vỡ vì Service trả về raw data.
Đề xuất Refactor:
Mọi hàm trong Repository Implementation phải trả về Domain Entity thông qua Mapper.toDomain().
### 4. Vấn đề: Chưa sử dụng Value Objects (VO)
Vị trí:
src/modules/accounting/application/dtos/create-finote.dto.ts (Dùng amount: number).
src/database/schema/accounting/finotes.schema.ts (Dùng numeric nhưng trong code xử lý như string/number).
Code Smell:
Bạn đã có class Money rất chuẩn ở @core, nhưng chưa dùng nó ở nơi cần thiết nhất là module Kế toán.
Đề xuất Refactor:
Entity Finote nên có thuộc tính amount: Money.
Khi khởi tạo Entity từ DTO, chuyển number -> new Money(amount).
Việc format tiền tệ (Intl.NumberFormat) nên nằm trong VO Money thay vì nằm trong Listener.
### 5. Vấn đề: Cross-Module Coupling (Phụ thuộc chéo)
Vị trí:
src/modules/employee/application/services/employee.service.ts (Inject UserService).
Code Smell:
Module Employee gọi trực tiếp UserService để tạo tài khoản.
Hệ quả:
Tạo ra sự phụ thuộc vòng hoặc chuỗi. Nếu module User thay đổi logic đăng ký, module Employee có thể bị crash.
Đề xuất Refactor:
Sử dụng Event-Driven: EmployeeService chỉ cần lưu hồ sơ nhân sự và bắn ra event EmployeeOnboarded.
Một Listener bên module User (EmployeeOnboardedListener) sẽ nhận event đó và tự động tạo User account.
### 6. Vấn đề: Logic hạ tầng nằm trong Listener
Vị trí:
src/modules/accounting/application/listeners/finote-created.listener.ts
Code Smell:
Listener đang làm quá nhiều việc: chuẩn bị data cho template, gọi PDF generator, gọi file storage, rồi lại tự tay insert vào DB.
Đề xuất Refactor:
Chuyển logic chuẩn bị dữ liệu in ấn vào một Domain Service hoặc hàm của Entity.
Listener chỉ đóng vai trò "trigger": Gọi PDFService, sau đó gọi FinoteRepository để đính kèm attachment.