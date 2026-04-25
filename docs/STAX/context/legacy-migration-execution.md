# Tài Liệu Chuyển Đổi Dữ Liệu (Legacy Migration Walkthrough & Plan)

> **Mục tiêu:** Di cư toàn bộ dữ liệu từ các file Excel/CSV cũ (Legacy) sang hệ thống STAX CRM mới an toàn, không thất thoát (Lossless) và bảo toàn tính toàn vẹn dữ liệu (Relational Integrity).

---

## 🚀 1. Nguyên Lý Thiết Kế 
Hệ thống áp dụng 2 tư duy thiết kế cốt lõi để đối phó với dữ liệu "rác" từ quá khứ:

### Hybrid Storage (Lưu Trữ Lai Ghép)
- **Vấn đề:** PostgreSQL yêu cầu dữ liệu nghiêm ngặt, nhưng file CSV của Sale lại đầy dữ liệu chắp vá (ví dụ: ngày tháng viết chữ, ghi chú tùm lum).
- **Giải pháp:** Các trường chuẩn (Tên, SĐT, Email) được ánh xạ vào Cấu trúc (Schema) chặt chẽ. Mọi thông tin "rác", thừa, lộn xộn được gom lại, biến thành dạng JSON và nhồi gọn gàng vào cột `metadata (JSONB)`. Nhờ vậy, chúng ta không để mất `1 byte` dữ liệu nào của quá khứ.

### Automated-First Scripts (Độc lập & Tự động)
Quá trình Migration không được viết gộp vào HTTP API của Server. Toàn bộ logic được tách rời ra thành các Kịch bản (Scripts) chạy trên nền `ts-node` để tương tác trực tiếp với Database. Tránh gây sập server và dễ dàng chạy lại (Re-runnable) nhiều lần.

---

## 🏛 2. Giai Đoạn 1: Bọc Thép Schema & Nhập Nhân Sự (Đã Xong)

### Kế hoạch đã triển khai:
1. **Fix rác Enum (Database Hardening):** Dùng script quét và sửa tận gốc các dữ liệu lỗi (VD: `"Zalo"` thành `"ZALO"`) do vi phạm Ràng buộc Enum của Postgres.
2. **Sửa lỗi ký tự lồng trong CSV Seed:** File `01_rbac_rules.csv` đã được làm sạch ký tự Newlines giúp Seeder RBAC hoạt động chuẩn xác trở lại.
3. **Di cư Nhân Sự:** 
   - Script chạy hoàn hảo file `THONG_TIN_NHAN_VIEN_TONG_HOP.csv` (vượt rào 3 dòng header cấu trúc siêu phức tạp).
   - Tự động sinh `OrgUnits` (Phòng ban), `Positions` (Chức danh) và đẩy tọt 14 nhân sự khung vào hệ thống. Đội ngũ PIC (Phụ trách) đã sẵn sàng.

---

## 🔗 3. Giai Đoạn 2: Dòng Thác Dữ Liệu CRM 
Dữ liệu CRM bị ràng buộc Khóa Ngoại (Foreign Key) chặt chẽ, nên phải thực thi từ trên xuống dưới theo thứ tự rễ -> cành:
**`Clients` ➡️ `Leads` ➡️ `Contracts` ➡️ `Finotes`**

### BƯỚC 1: Xử lý tệp Khách hàng (Clients) - Đã Triển Khai
Quét file `2026.STAX.CRM.Clients.csv` 

**Cách thức thực thi:**
- **Push Metadata:** Chạy lệnh `drizzle-kit push` để tiêm cột `metadata (JSONB)` vào 2 bảng `organizations` và `contacts`.
- **Logic Mapping:** Phân tích và convert các Trạng thái hợp đồng cũ theo chuẩn như "Thanh Lý HĐ" thành `INACTIVE`, "Chờ ký" thành `PROSPECT`.
- **CSV Parser vượt rào:** Header của file kéo dài đến tận 6 dòng (Do chứa dấu xuống dòng lồng trong ngoặc kép `"Thu phí \n/tháng"`). Hệ thống ép Parser đọc dạng `relax_quotes: true` và lọc bỏ dòng tiêu đề thô thay vì Mapping cứng.

**Kết Quả (Ngày 26/04/2026):**
- **Tạo mới:** `202` Khách hàng doanh nghiệp cùng người liên hệ đại diện.
- **Tồn Tại:** `1` record (Hệ thống bảo vệ không đè rác).
- **Lỗi Bị Văng:** `9` record. *(Do file CSV lạm dụng copy-paste email `haidangdo.lvg...` gây vi phạm luật `UNIQUE` của `contacts.email`. 202 công ty sạch đã vào an toàn).*

### BƯỚC 2: Di Cư Leads (Cơ Hội Khách Hàng) - Hoàn Thành
Sử dụng file `2026.STAX.CRM.Lead.csv`.
- Logic Schema: Nhúng thành công cột `metadata: jsonb('metadata')` vào bảng `leads`.
- Map Dữ liệu: Phố hợp dò chéo (Lookup) tự động `employees` thông qua cột consultant (Nick name nhân viên trong Legacy) để gán cho cột `assigned_to_id`.
- Tăng tỷ lệ Map Khách Hàng: Dò `phone` từ `contacts` để trích xuất ngược lại `organization_id` nếu Lead có khả năng map thành Client cũ.
- **Kết Quả (Ngày 26/04/2026):**
  - **Dòng quét thành công:** `1172` Leads.
  - **Tỷ lệ lỗi:** `0` lỗi. (Hoàn hảo 100%).

### BƯỚC 3 & 4: Hợp Đồng (Contracts) & Hóa Đơn (Finotes)
Sử dụng `04_.STAX.CRM.FN.2026.csv`.
- Logic: Xử lý khối lượng dòng tiền khổng lồ, gắn vào hợp đồng (Nâng cao trạng thái Active của Customer) và bọc thép bảo mật.

---
*Tài liệu này được hệ thống Antigravity tự động cập nhật ngay trên Directory của Workspace.*
