Vì bạn đang ở trạng thái **"Code vẫn chạy, chưa sửa gì cả"**, đây là thời điểm nhạy cảm. Nếu sửa lung tung sẽ rất dễ hỏng cả dự án (broken build) và khiến bạn nản chí.

Để chuyển đổi từ code hiện tại sang mô hình **Pro (DDD/Clean Arch)** một cách an toàn nhất, bạn hãy làm theo lộ trình **"Chiến thuật Vết Dầu Loang" (Strangler Fig Pattern)**: Tách dần từng phần nhỏ ra khỏi khối code lớn, giữ cho hệ thống luôn chạy được sau mỗi bước.

Dưới đây là 5 bước cụ thể để bạn bắt đầu ngay bây giờ:

---

### BƯỚC 1: Chuẩn bị "Khung xương" (Folder Structure)

Đừng vội sửa logic. Hãy tạo các thư mục rỗng trước để hình dung kiến trúc.

1.  **Tạo các thư mục Module mới:**
    *   `src/modules/organization/` (Sẽ chứa Clinic)
    *   `src/modules/patient/` (Sẽ chứa Patient)
    *   `src/modules/medical-staff/` (Sẽ chứa Dentist)
    *   `src/modules/dental-treatment/` (Đây là nhà mới của Dental cũ)

2.  **Trong mỗi module trên, tạo sẵn cấu trúc Level 2 (Standard):**
    *   `domain/entities`, `domain/repositories`
    *   `infrastructure/persistence`
    *   `application/services` (hoặc use-cases)

*(Lúc này code vẫn chạy bình thường vì bạn chỉ mới tạo thư mục rỗng).*

---

### BƯỚC 2: Di cư Dữ liệu (Database Schema)

Drizzle ORM của bạn đang định nghĩa tất cả trong `ortho.schema.ts`. Hãy chia nhỏ nó ra. Đây là bước dễ nhất và ít rủi ro nhất.

1.  **Tách file `src/database/schema/ortho.schema.ts`**:
    *   Copy đoạn code định nghĩa bảng `clinics` sang file mới: `src/modules/organization/infrastructure/persistence/schema/clinics.schema.ts`.
    *   Copy đoạn code định nghĩa bảng `patients` sang: `src/modules/patient/infrastructure/persistence/schema/patients.schema.ts`.
    *   Copy đoạn code định nghĩa bảng `dentists` sang: `src/modules/medical-staff/infrastructure/persistence/schema/dentists.schema.ts`.
    *   Để lại `cases` và `treatment_steps` ở `dental-treatment` (hoặc giữ tên file cũ tạm thời nhưng xóa các bảng đã chuyển).

2.  **Cập nhật `src/database/schema/index.ts`**:
    *   Sửa lại đường dẫn export để trỏ về các file mới.

*(Chạy thử lại app. Nếu Drizzle không báo lỗi schema nghĩa là bạn đã tách file thành công).*

---

### BƯỚC 3: "Xẻ thịt" Repository khổng lồ

File `DrizzleOrthoRepository` của bạn đang làm quá nhiều việc. Hãy chia nhỏ nó.

1.  **Tạo Repository cho Organization:**
    *   Tạo Interface `IClinicRepository` trong `src/modules/organization/domain/repositories/`.
    *   Tạo `DrizzleClinicRepository` trong `infrastructure`, copy các hàm `findClinicByCode`, `createClinic` từ `DrizzleOrthoRepository` sang đây.

2.  **Tương tự cho Patient và Dentist:**
    *   Tạo `IPatientRepository` và `DrizzlePatientRepository` (move hàm `findPatientByCode`, `createPatient`).
    *   Tạo `IDentistRepository` và `DrizzleDentistRepository` (move hàm `findDentist`, `createDentist`).

3.  **Đăng ký Module mới:**
    *   Tạo `OrganizationModule`, `PatientModule`, `MedicalStaffModule`.
    *   Đăng ký các Repository vừa tạo vào `providers` và `exports` của từng module tương ứng.

*(Lúc này `DrizzleOrthoRepository` cũ vẫn còn đó, nhưng code bên trong vơi đi nhiều. Các module mới đã sẵn sàng phục vụ).*

---

### BƯỚC 4: Refactor Service (Logic nghiệp vụ)

Đây là bước quan trọng nhất: Chuyển logic từ `DentalService` cũ sang các Service mới.

1.  **Viết Domain Service cho các module con:**
    *   Trong `OrganizationModule`, viết `ClinicService` với hàm `ensureClinicExists`.
    *   Trong `PatientModule`, viết `PatientService` với hàm `ensurePatientExists`.
    *   *(Logic này lấy từ đoạn code dài ngoằng trong `DentalService.processZipUpload`)*.

2.  **Tạo Use Case Upload:**
    *   Trong `DentalTreatmentModule` (module Dental cũ), tạo file `upload-case.use-case.ts`.
    *   Inject `ClinicService`, `PatientService` vào Use Case này.
    *   Copy logic upload từ `DentalService` sang, nhưng thay thế các đoạn code tạo clinic/patient thủ công bằng cách gọi hàm của các Service mới.

---

### BƯỚC 5: Dọn dẹp & Kết nối (Wiring)

1.  **Sửa `DentalModule` (nay là `TreatmentModule`):**
    *   Import `OrganizationModule`, `PatientModule`, `MedicalStaffModule` vào `imports`.
    *   Thay thế `DentalService` trong Controller bằng `UploadCaseUseCase`.

2.  **Xóa code thừa:**
    *   Xóa các hàm đã chuyển đi trong `DrizzleOrthoRepository`.
    *   Xóa các logic cũ trong `DentalService` (hoặc xóa hẳn file này nếu đã chuyển hết sang Use Cases).

---

### Tóm lại: Bạn nên bắt đầu file nào đầu tiên?

Nếu tôi là bạn, tôi sẽ mở file này đầu tiên:
👉 **`src/database/schema/ortho.schema.ts`**

Tại sao? Vì Data là gốc rễ. Khi bạn tách được Schema của Clinic, Patient ra riêng, tư duy của bạn sẽ tự động thấy rõ biên giới giữa các Module. Sau đó, việc tách Repository và Service sẽ diễn ra rất tự nhiên.

**Lời khuyên:** Đừng cố làm hết 1 lượt. Làm xong Bước 2 (Schema), hãy commit code. Làm xong Bước 3 (Repo), hãy commit code. Đảm bảo app luôn chạy được `npm run start:dev` sau mỗi bước. Chúc bạn thành công!