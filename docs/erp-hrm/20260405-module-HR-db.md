Module **HRM (Nhân sự & Tổ chức)** trong sơ đồ trên được thiết kế theo chuẩn **"Position-based Architecture" (Kiến trúc dựa trên Vị trí)** - một tiêu chuẩn của các hệ thống ERP/HRM Enterprise (cấp doanh nghiệp lớn) như SAP hay Workday. 

Sự khác biệt lớn nhất của kiến trúc này là: **Tách biệt hoàn toàn giữa "Người" (Employee) và "Cái ghế" (Position)**. 

Dưới đây là giải thích chi tiết từng cụm, kèm ví dụ Đúng/Sai và mô phỏng luồng chạy thực tế.

---

### 1. GIẢI THÍCH CHI TIẾT CÁC MỐI QUAN HỆ & VÍ DỤ ĐÚNG/SAI

#### A. Cụm Tổ chức & Vị trí (Org Units, Job Titles, Grades, Positions)
Đây là phần khung xương của công ty. Bạn phải xây nhà và kê ghế trước khi mời người vào ngồi.

*   **`org_units` (Phòng ban):** Là cấu trúc cây. Bảng này tự liên kết với chính nó (`parentId`).
    *   *Ví dụ ĐÚNG:* Công ty STAX (ID: 1) -> Khối Công Nghệ (ID: 2, Parent: 1) -> Phòng Phát triển (ID: 3, Parent: 2).
    *   *Ví dụ SAI (Lỗi vòng lặp):* Phòng Phát triển làm Parent của Khối Công Nghệ. Lúc này vẽ sơ đồ tổ chức (Org Chart) hệ thống sẽ bị treo vì vòng lặp vô tận.
*   **`job_titles` (Chức danh chuẩn) & `grades` (Ngạch bậc):** Định nghĩa từ điển chức danh và cấp bậc (VD: Junior, Mid, Senior).
*   **`positions` (Vị trí - "Cái ghế"):** Đây là bảng quan trọng nhất. Một vị trí là sự kết hợp của: Phòng ban nào + Chức danh gì + Cấp bậc nào.
    *   *Ví dụ ĐÚNG:* Vị trí "Lập trình viên Backend Senior" (ID: 100) nằm ở Phòng Phát triển (orgUnitId: 3), Chức danh là Lập trình viên (jobTitleId: 5), Cấp bậc Level 4 (gradeId: 4). Giới hạn (headcountLimit) = 2 người.
    *   *Ví dụ SAI (Lỗi kiến trúc nghiệp dư):* Bỏ qua bảng `positions`, gắn trực tiếp trường `chuc_danh = "Lập trình viên Backend"` vào bảng `employees`. Về sau công ty đổi tên chức danh thành "Kỹ sư phần mềm", lập trình viên phải đi Update (cập nhật) hàng ngàn nhân viên thay vì chỉ đổi tên ở 1 chỗ duy nhất.

#### B. Cụm Ngạch Lương (Grades, Salary Scales)
*   **`salary_scales` (Thang bảng lương):** Gắn liền với `grades` (Cấp bậc).
    *   *Ví dụ ĐÚNG:* Tháng 1/2025, công ty quy định Grade 1 lương cơ bản 10 triệu. Hệ thống tự động tính lương cho tất cả nhân viên ngồi ở Position có Grade 1.
    *   *Ví dụ SAI:* Nhập thẳng lương cơ bản `10.000.000` vào bảng `employees`. Khi nhà nước tăng lương tối thiểu, HR phải mò vào sửa tay cho từng người một.

#### C. Cụm Nhân sự (Users, Employees, Locations)
*   **`employees` (Hồ sơ nhân sự):** Đây là con người thực.
    *   `userId`: Nối với tài khoản để đăng nhập (Có người là nhân viên nhưng không có tài khoản đăng nhập, VD: Cô lao công, Bác bảo vệ).
    *   `positionId`: Nối với bảng `positions` (Người A ngồi vào Ghế B).
    *   `managerId`: Liên kết vòng (Chỉ định ai quản lý ai).
    *   *Ví dụ ĐÚNG:* Nhân viên Nguyễn Văn A (ID: 5) có `managerId = 2` (Trần Văn B). B sẽ duyệt phép cho A.
    *   *Ví dụ SAI:* Ghi tên sếp trực tiếp dạng Text: `manager = "Trần Văn B"`. Sếp B nghỉ việc, thay bằng sếp C -> Phải đi sửa Text cho toàn bộ lính của sếp B.

#### D. Cụm Đánh giá & Thăng tiến (Performance Reviews)
*   **`performance_reviews`**: Đánh giá nhân sự định kỳ.
    *   Liên kết với nhân viên được đánh giá (`employeeId`), người đánh giá (`reviewerId`), và Đề xuất thăng chức lên vị trí mới (`proposedPositionId`).

---

### 2. MÔ PHỎNG LUỒNG LÀM VIỆC BẰNG BẢNG (WORKFLOW)

Hãy xem cách hệ thống hoạt động thực tế qua câu chuyện: **Tuyển dụng & Thăng chức cho nhân viên Nguyễn Văn A**.

#### BƯỚC 1: XÂY DỰNG KHUNG TỔ CHỨC (MASTER DATA)
*HR tạo Phòng ban, Cấp bậc, Chức danh và Kê "Cái ghế" (Position).*

**Bảng `org_units`**
| id | name | parentId |
|---|---|---|
| 1 | Khối Công Nghệ | null |
| 2 | Đội Lập trình | 1 |

**Bảng `grades`**
| id | levelNumber | name | Lương tương ứng (ở bảng salary_scales) |
|---|---|---|---|
| 10 | 1 | Junior | 10,000,000 |
| 20 | 2 | Middle | 20,000,000 |

**Bảng `positions` (HR tạo 2 cái ghế trong Đội Lập trình)**
| id | code | name | orgUnitId | jobTitleId | gradeId | headcountLimit |
|---|---|---|---|---|---|---|
| **100** | DEV-JUN | Lập trình viên Junior | 2 | Lập trình viên | **10** | 5 (được tuyển 5 người) |
| **200** | DEV-MID | Lập trình viên Middle | 2 | Lập trình viên | **20** | 2 (được tuyển 2 người) |

---

#### BƯỚC 2: TIẾP NHẬN NHÂN VIÊN MỚI (ONBOARDING)
*Nguyễn Văn A trúng tuyển vị trí Junior. Hệ thống cấp tài khoản và xếp A vào "Cái ghế" số 100.*

**Bảng `users` (Tạo tài khoản đăng nhập)**
| id | username | email |
|---|---|---|
| 999 | nva | nva@stax.vn |

**Bảng `employees` (Hồ sơ nhân sự của A)**
| id | userId | fullName | positionId (Cái ghế) | managerId (Sếp trực tiếp) |
|---|---|---|---|---|
| 50 | 999 | Nguyễn Văn A | **100** *(Ghế Junior)* | 10 *(ID của ông Trưởng nhóm)* |

👉 **Kết quả hệ thống tự động hiểu:** 
Nguyễn Văn A thuộc Đội Lập trình (do ghế 100 thuộc đơn vị 2). Lương cơ bản của A là 10,000,000đ (do ghế 100 gắn với cấp bậc 10).

---

#### BƯỚC 3: ĐÁNH GIÁ NĂNG LỰC (PERFORMANCE REVIEW)
*Sau 1 năm, ông Trưởng nhóm (ID: 10) đánh giá A làm việc xuất sắc và đề xuất thăng chức lên Middle.*

**Bảng `performance_reviews`**
| id | employeeId | reviewerId | score | comments | proposedPositionId (Đề xuất ghế mới) | status |
|---|---|---|---|---|---|---|
| 1 | 50 (A) | 10 (Sếp) | 9.5 | Code rất tốt, ít bug | **200** *(Ghế Middle)* | PENDING |

---

#### BƯỚC 4: DUYỆT THĂNG CHỨC (PROMOTION)
*Giám đốc vào xem phiếu đánh giá (ID: 1), ấn nút "APPROVE". Hệ thống tự động làm việc sau:*
1. Status của phiếu đánh giá chuyển thành `APPROVED`.
2. Hệ thống cập nhật bảng `employees` của nhân viên A.

**Bảng `employees` (Hồ sơ nhân sự của A SAU KHI THĂNG CHỨC)**
| id | userId | fullName | positionId (Cái ghế) | managerId |
|---|---|---|---|---|
| 50 | 999 | Nguyễn Văn A | **200** *(Đã chuyển sang ghế Middle)* | 10 |

👉 **Hiệu ứng Domino của kiến trúc chuẩn:**
Ngay khi `positionId` đổi thành **200**, hệ thống nhân sự - tiền lương lập tức cập nhật:
* A giờ đang ở Grade 20.
* Bảng lương tháng này tự động tính theo mức 20,000,000đ mà không cần kế toán phải gõ tay sửa lại lương.
* "Cái ghế" số 100 (Junior) trống ra 1 chỗ, bộ phận Tuyển dụng (TA) nhìn vào Dashboard sẽ thấy: *Headcount limit là 5, hiện chỉ có 4 người ngồi, cần tuyển gấp 1 người bù vào!*

### TỔNG KẾT DÀNH CHO BẠN
Khi mang sơ đồ và giải thích luồng hoạt động này cho khách hàng (STAX), bạn hãy chốt hạ một câu thế này: 
> *"Hệ thống được thiết kế không phải để quản lý 'Con người' một cách thủ công, mà là quản lý 'Khung năng lực và Vị trí'. Con người có thể nghỉ việc, chuyển phòng ban, nhưng cấu trúc công ty (Positions) luôn giữ vững. Việc này giúp STAX dễ dàng scale từ 100 lên 5,000 nhân viên mà hệ thống không bị gãy đổ."*