# 🤝 UNIFIED ONBOARDING (QUY TRÌNH KÍCH HOẠT KHÁCH HÀNG TỰ ĐỘNG)

## 1. MỤC TIÊU (OBJECTIVE)
Chuyển đổi trạng thái từ "Đã chốt hợp đồng" (Won Lead) sang "Khách hàng đang hoạt động" với đầy đủ hạ tầng cần thiết một cách tự động, giảm thiểu sai sót do con người và rút ngắn thời gian triển khai dịch vụ.

---

## 2. QUY TRÌNH (WORKFLOW)

Khi sự kiện `CLIENT_ONBOARDED` được phát hành từ CRM, hệ thống sẽ tự động thực hiện:

1.  **Thiết lập Tài chính (Billing Setup)**:
    *   Tự động tạo kỳ thanh toán đầu tiên dựa trên giá trị hợp đồng.
    *   Thiết lập hạn mức công nợ (Credit Limit).
2.  **Thiết lập Đội ngũ (Team Provisioning)**:
    *   Gán các vị trí (Positions) đã chọn cho doanh nghiệp dựa trên `ServiceAssignment`.
    *   Thông báo cho các trưởng bộ phận liên quan qua Slack/Telegram.
3.  **Khởi tạo Không gian số (Workspace Ready)**:
    *   Tạo thư mục lưu trữ riêng (Storage Bucket).
    *   Khởi tạo tài khoản Admin cho phía khách hàng.

---

## 3. KIẾN TRÚC KỸ THUẬT (TECHNICAL DESIGN)

### A. Sự kiện kích hoạt (Trigger)
*   **Event**: `CLIENT_ONBOARDED`
*   **Payload**: `orgId`, `contractId`, `contractNumber`.

### B. Onboarding Orchestrator
Một `OnboardingConsumer` sẽ nghe sự kiện và điều phối các Service:
*   `AccountingService.initBilling()`
*   `OrgStructureService.assignTeam()`
*   `NotificationService.sendWelcome()`

---

## 4. LỘ TRÌNH TRIỂN KHAI (IMPLEMENTATION STEPS)

1.  **Bước 1**: Tạo module `onboarding` mới.
2.  **Bước 2**: Implement `OnboardingConsumer` để xử lý sự kiện bất đồng bộ.
3.  **Bước 3**: Xây dựng `billing-setup` logic trong module Accounting.
4.  **Bước 4**: Xây dựng `team-setup` automation.
5.  **Bước 5**: Kiểm chứng bằng cách chốt một Lead mẫu và quan sát quá trình kích hoạt tự động.

---
*Tài liệu được khởi tạo ngày 26/04/2026 bởi Antigravity AI.*
