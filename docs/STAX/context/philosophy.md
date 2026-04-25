# STAX Business Philosophy & Core Principles

Tài liệu này lưu giữ những tư duy cốt lõi và triết lý thiết kế hệ thống STAX, giúp định hướng cho mọi quyết định nâng cấp tính năng trong tương lai.

---

## 1. Triết lý Entity vs. Process (Thực thể và Tiến trình)
Đây là sự khác biệt giữa một phần mềm quản lý dữ liệu đơn thuần và một hệ thống **Enterprise Resource Planning (ERP)** chuyên nghiệp.

*   **Entity (DNA - Nguồn sự thật):** Là những thông tin định danh không đổi (Tên khách hàng, MST, SĐT). Chúng được lưu tập trung tại bảng `Organizations` và `Contacts`.
*   **Process (Tiến trình - Hành động):** Là những gì chúng ta "làm" với Thực thể đó (Tư vấn Lead, Ký Hợp đồng, Thu tiền Finote).
*   **Lợi ích:** 
    - Không bao giờ phải copy dữ liệu khi chuyển giai đoạn.
    - Dữ liệu lịch sử (Notes, Ghi chú) luôn được giữ nguyên từ lúc khách còn là Lead cho đến khi thành khách hàng thân thiết.
    - Dễ dàng triển khai mô hình Bán thêm (Cross-selling).

---

## 2. Mô hình "Role-based Organization" (SaaS Multi-tenancy)
Hệ thống STAX được thiết kế để có thể phục vụ chính STAX và hàng ngàn khách hàng khác trên cùng một bộ code.

*   **Internal Organization (Bản ghi STAX):** Đóng vai trò là Chủ thể/Người cung cấp dịch vụ. Mọi nhân viên (Employees) và Phòng ban (OrgUnits) của STAX đều neo vào đây.
*   **External Organizations (Khách hàng):** Đóng vai trò là Khách thể/Người sử dụng dịch vụ.
*   **Data Isolation:** Sử dụng `organization_id` trên mọi bảng nghiệp vụ để đảm bảo dữ liệu của Khách hàng A không bao giờ bị lộ sang Khách hàng B.

---

## 3. Tư duy "Service Orchestrator"
Service Layer trong hệ thống STAX không chỉ làm CRUD. Nó đóng vai trò là **"Người điều phối vòng đời"**.

*   Khi một sự kiện xảy ra (ví dụ: Chốt Hợp đồng), Service sẽ điều phối hàng loạt hành động liên đới:
    1. Cập nhật trạng thái Lead.
    2. Kích hoạt trạng thái Organization thành ACTIVE.
    3. Sinh Hợp đồng.
    4. Gán đội ngũ phục vụ.
    5. Bắn Event để sinh thông báo/email.
*   Điều này giúp hệ thống tự vận hành, giảm bớt thao tác tay cho nhân viên.

---

## 5. Tư duy "Pháo đài vs CRUD" (Fortress Mindset)
Chúng ta áp dụng cách tiếp cận thực dụng trong phát triển phần mềm:
*   Nếu một tính năng chỉ là CRUD đơn giản (vd: danh mục tỉnh thành), đừng tốn quá nhiều thời gian thiết kế DDD.
*   Nếu tính năng đó là **Lõi sinh tiền hoặc Lõi dữ liệu** (vd: Lead Intake, Kế toán, Phân quyền), chúng ta phải xây nó chặt chẽ như một **Pháo đài**. Mọi ngõ ngách đều phải có Unit Test, Validation và Logging.

> **📝 Châm ngôn của Team Backend:** 
> *"Kiến trúc không phải là đích đến, kiến trúc là công cụ để giải quyết bài toán kinh doanh. Đừng tốn 2 ngày để thiết kế DDD cho một tính năng chỉ cần 2 tiếng để viết CRUD. Nhưng nếu đó là trái tim của hệ thống, hãy viết nó như một pháo đài."*

---

## 6. Security by Design & Data Privacy
Dữ liệu của khách hàng là tài sản quý giá nhất. Chúng ta bảo vệ nó bằng kỹ thuật:
*   **Standardized Response Mapping:** Tuyệt đối không gửi `Entity` thô về Client. Phải qua `DTO Mapper` để lọc bỏ các trường nhạy cảm (Password, Internal IDs).
*   **Tenant Isolation:** Filter dữ liệu tự động theo `organization_id` ngay từ tầng Repository.

---
*Tài liệu này được đúc kết từ những phiên thảo luận nghiệp vụ quan trọng nhất của dự án.*
