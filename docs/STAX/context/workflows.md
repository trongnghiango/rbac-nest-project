# STAX Business Workflows & Strategic Roadmap (v2)

Bản tài liệu này định nghĩa cách STAX vận hành một cách tối giản, hiệu quả và chuyên nghiệp, tập trung vào việc giảm tải áp lực cho nhân viên và tối ưu hóa trải nghiệm khách hàng.

---

## 🛡️ NGUYÊN TẮC GIÁM SÁT CHUNG (CROSS-CUTTING CONCERNS)
Mọi luồng nghiệp vụ dưới đây đều được giám sát bởi hệ thống **Audit Log**:
*   **Traceability:** Mọi hành động thay đổi trạng thái (Won, Paid, Assigned) đều lưu vết User thực hiện.
*   **Data Integrity:** Lưu vết dữ liệu trước và sau khi thay đổi để phục vụ hậu kiểm.
*   **Security:** Cảnh báo các hành động nhạy cảm (Gán quyền Admin, Xóa dữ liệu).

---

## 1. Luồng Tiếp nhận Thông minh (Intelligent Intake)
**Mục tiêu:** Giảm 80% thời gian nhập liệu, tăng độ chính xác dữ liệu khách hàng.

### [Workflow]
1.  **Quick-Capture:** Nhân viên dán snippet chat/email vào ô "Ghi chú nhanh".
2.  **Auto-Matching:** 
    - Nếu SĐT đã có trong hệ thống -> Tự động gắn Lead vào **Organization** hiện tại.
    - Nếu SĐT mới -> Tự động khởi tạo bộ 3: **Contact** + **Organization (Prospect)** + **Lead**.
3.  **Source Tracking:** Tự động gắn nhãn nguồn (Zalo, Ads, Người quen giới thiệu).

---

## 2. Luồng Onboarding & Chuyển đổi (Lead-to-Client)
**Mục tiêu:** Giúp Sales chốt deal nhanh và đẩy việc cho Ops mà không cần gửi email/chat rườm rà.

### [Workflow]
1.  **The "Big Bang" Moment:** Sales nhấn nút `CLOSE WON`:
    -   Hệ thống chuyển `Organization` thành `ACTIVE_CLIENT`.
    -   Tự động tạo `Contract` (Hợp đồng) kèm các điều khoản phí.
    -   **Audit Log:** Ghi nhận hành động [LEAD.CLOSE_WON] kèm snapshot hợp đồng.
2.  **Assignment:** Hệ thống tự động gán **Chuyên viên** và **Leader**.

---

## 3. Luồng Quản lý Dòng tiền & Gạch nợ (Billing & Collection)
**Mục tiêu:** Kế toán chỉ cần nhìn Bank Statement là có thể dập nợ cho hàng trăm khách hàng.

### [Workflow]
1.  **Cash Entry:** Khi tiền về tài khoản Ngân hàng, kế toán tạo **Cash Transaction**.
2.  **Smart Matching:** 
    - Kế toán chọn các hóa đơn (`Finotes`) đang nợ.
    - Nhấn `ALLOCATE`: Tiền từ Sổ Quỹ tự động "gạch nợ" cho Hóa đơn.
    - **Audit Log:** Ghi nhận hành động [PAYMENT.ALLOCATED] để đối soát dòng tiền.

---

## 4. Luồng Quản lý Hiệu suất & Activity Feed
**Mục tiêu:** Tổng hợp mọi biến động thành một dòng thời gian hội tụ (Timeline).

### [Workflow]
1.  **Omnichannel Feed:** Mọi hành động (từ Audit Log) được hiển thị trên Timeline của Organization đó.
2.  **Service Quality:** Theo dõi `Deadline_At` của các Task. Nếu Task đỏ -> Hệ thống cảnh báo cho Leader.

---

## 💡 Tư duy Tối ưu (Dành cho Dev & Manager)
-   **Đừng bắt nhân viên nhập Title:** Hệ thống hãy tự tạo Title theo format chuẩn.
-   **Tận dụng QR Code:** Mỗi Finote kèm mã QR chứa ID_FINOTE.
-   **Reconciliation Tự động:** Khi tiền về có nội dung chứa ID_FINOTE, hệ thống tự động gạch nợ.

---
*Tài liệu được cập nhật ngày 26/04/2026 bởi Antigravity AI.*
