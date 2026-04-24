# STAX Enterprise Architecture (v2.1) - The Clean Future

Tài liệu này định nghĩa cấu trúc thượng tầng của dự án STAX, tuân thủ Clean Architecture và DDD để đảm bảo hệ thống có thể mở rộng (Scale) và bảo trì trong 10 năm tới.

## 1. Triết lý thiết kế (Design Philosophy)
Chúng ta xây dựng hệ thống dựa trên 3 trụ cột:
*   **Domain-Driven Design (DDD):** Nghiệm vụ là trung tâm. Code phải phản ánh đúng ngôn ngữ của chuyên viên thuế/kế toán.
*   **Clean Architecture:** Logic nghiệp vụ không phụ thuộc vào Database (Drizzle), Framework (NestJS) hay UI/API.
*   **Event-Driven & Port-Adapter:** Các module giao tiếp qua Events (Async) hoặc Ports (Sync) để triệt tiêu Circular Dependency.

## 2. Mô hình Kinh doanh áp dụng (Business Model)
Hệ thống không chỉ là ERP, mà là một **"Operation Automation Platform"** cho ngành thuế với các luồng chính:
1.  **Subscription Service:** Thu phí kế toán định kỳ (Monthly/Quarterly) tự động.
2.  **Compliance as a Service:** Tự động hóa việc nộp tờ khai và theo dõi thời hạn (Deadline-driven).
3.  **Financial Reconciliation:** Đối soát ngân hàng và gạch nợ tự động dựa trên giao dịch thực.

## 3. Cấu trúc Module Kế toán 4 lớp (Cốt lõi mới)
Đây là kiến trúc giúp STAX dẫn đầu về độ chính xác:
-   **Layer 1 (Finote Header):** Quản lý nợ tổng thể.
-   **Layer 2 (Finote Items):** Quản lý chi tiết từng đầu mục chi phí phát sinh.
-   **Layer 3 (Cash Flow Ledger):** Sổ quỹ thực tế, lưu mọi biến động tiền mặt/ngân hàng.
-   **Layer 4 (Mapping/Allocation):** Móc nối linh hoạt giữa Dòng tiền và Hóa đơn.

## 4. Quản lý Giao dịch (Transaction Strategy)
Sử dụng **Async Local Storage (ALS)** để quản lý Transaction "tàng hình". 
-   Giữ cho Service Interface sạch sẽ (không phải truyền `tx` vào mọi nơi).
-   Đảm bảo tính toàn vẹn (ACID) cho các luồng phức tạp như Gạch nợ hoặc Onboarding khách hàng.

## 5. Chiến lược Kiểm thử (Testing)
Xem chi tiết tại `TEST_STRATEGY.md`. Mọi logic "nguy hiểm" liên quan đến tiền và thuế PHẢI có Unit Test bao phủ 100%.

---
*Cập nhật lần cuối: 2026-04-24 by Antigravity*
