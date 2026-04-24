# STAX Business Workflows & Strategic Roadmap (v2)

Bản tài liệu này định nghĩa cách STAX vận hành một cách tối giản, hiệu quả và chuyên nghiệp, tập trung vào việc giảm tải áp lực cho nhân viên và tối ưu hóa trải nghiệm khách hàng.

---

## 1. Luồng Onboarding & Chuyển đổi (Lead-to-Client)
**Mục tiêu:** Giúp Sales chốt deal nhanh và đẩy việc cho Ops mà không cần gửi email/chat rườm rà.

### [Workflow]
1.  **Discovery:** Tiếp nhận yêu cầu -> Tạo **Contact** (SĐT/Email).
2.  **Lead Management:** Tạo **Lead** -> Tư vấn gói (Trọn gói/Pháp lý).
3.  **The "Big Bang" Moment:** Sales nhấn nút `CLOSE WON`:
    -   Hệ thống chuyển `Organization` thành `ACTIVE_CLIENT`.
    -   Tự động tạo `Contract` (Hợp đồng) kèm các điều khoản phí.
    -   **Tự động tạo Billing Template:** Thiết lập sẵn lịch thu phí (ví dụ: Thu 900k vào ngày 5 hàng tháng).
4.  **Assignment:** Hệ thống tự động gán **Chuyên viên** và **Leader** dựa trên loại hình dịch vụ khách đã mua.

---

## 2. Luồng Vận hành Kế toán định kỳ (Recurring Compliance)
**Mục tiêu:** Đảm bảo 100% khách hàng đều được nộp tờ khai thuế đúng hạn mà chuyên viên không cần nhớ lịch.

### [Workflow]
1.  **Auto Generation:** Vào ngày 20 hàng tháng/quý:
    -   Worker tự động quét các `ACTIVE_CLIENT`.
    -   Sinh ra các **Task** (Ví dụ: "Lập tờ khai VAT quý 1 cho Công ty A").
    -   Sinh ra các **Finote Header** (Phiếu báo phí dịch vụ kế toán).
2.  **Execution:** Chuyên viên hoàn thành nghiệp vụ -> Cập nhật `Status = DONE`.
3.  **Evidence:** Chuyên viên upload tờ khai thuế (file XML/PDF) vào phần `Evidence` của Task để Leader kiểm tra.

---

## 3. Luồng Quản lý Dòng tiền & Gạch nợ (Billing & Collection)
**Mục tiêu:** Kế toán chỉ cần nhìn Bank Statement là có thể dập nợ cho hàng trăm khách hàng.

### [Workflow]
1.  **Invoice Issuance:** Hệ thống gửi Email/Zalo thông báo phí (Link Finote) cho khách hàng.
2.  **Cash Entry:** Khi tiền về tài khoản Ngân hàng:
    -   Kế toán tạo 1 **Cash Transaction** (Dòng tiền thực).
3.  **Smart Matching:** 
    -   Kế toán chọn các hóa đơn (`Finotes`) đang nợ của khách đó.
    -   Nhấn `ALLOCATE`: Tiền từ Sổ Quỹ tự động "gạch nợ" cho Hóa đơn.
    -   Hệ thống tự động chuyển trạng thái `Finote -> PAID`.
4.  **Auto Remind:** Các hóa đơn quá hạn 5 ngày -> Hệ thống tự động gửi tin nhắn nhắc nợ nhẹ nhàng cho khách.

---

## 4. Luồng Quản lý Hiệu suất (Overload Prevention)
**Mục tiêu:** Leader biết được ai đang quá tải để điều phối nhân sự.

### [Workflow]
1.  **Load Dashboard:** Leader xem biểu đồ số lượng Khách hàng/Chuyên viên.
2.  **Service Quality:** Theo dõi `Deadline_At` của các Task báo cáo thuế. Nếu Task đỏ (quá hạn) -> Hệ thống cảnh báo cho Leader để hỗ trợ kịp thời.

---

## 💡 Tư duy Tối ưu (Dành cho Dev & Manager)
-   **Đừng bắt nhân viên nhập Title:** Hệ thống hãy tự tạo Title theo format: `[Tháng/Năm] - Phí dịch vụ - [Tên Công Ty]`.
-   **Tận dụng QR Code:** Mỗi Finote khi gửi cho khách nên có 1 mã QR Ngân hàng (VietQR) chứa số tiền và nội dung chuyển khoản là `ID_FINOTE`. 
-   **Reconciliation Tự động:** Khi tiền về có nội dung chứa `ID_FINOTE`, hệ thống sẽ tự động thực hiện **Workflow 3** mà không cần kế toán nhấn nút. 

---
*Tài liệu này là kim chỉ nam để chúng ta triển khai các API và UI sau này. Mọi code viết ra phải phục vụ việc đơn giản hóa các luồng trên.*
