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

## 4. Kiểm soát Công nợ (Zero-foul Finance)
Tách biệt hoàn toàn giữa **Công nợ (Dồn tích)** và **Dòng tiền (Thực thu)**.
*   `Finote`: Thể hiện nghĩa vụ thanh toán.
*   `Cash Transaction`: Thể hiện tiền thực tế vào tài khoản.
*   `Allocation`: Việc gạch nợ phải minh bạch, một dòng tiền có thể phân bổ cho nhiều hóa đơn.

---
*Tài liệu này được đúc kết từ những phiên thảo luận nghiệp vụ quan trọng nhất của dự án.*
