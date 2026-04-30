# 🛠️ STAX Technical Stack
Tài liệu này liệt kê các công nghệ cốt lõi được sử dụng để xây dựng hệ thống STAX và lý do lựa chọn chúng.

## 1. Backend Framework: NestJS
*   **Lý do:** Hỗ trợ quy chuẩn hóa kiến trúc (Modular, Dependency Injection), giúp dự án dễ bảo trì khi phình to.
*   **Kỹ thuật đặc biệt:** Sử dụng **Async Local Storage (ALS)** để quản lý nờ `Transaction Container`. Giúp code sạch, không cần truyền tham số `tx` thủ công.

## 2. Database & ORM: PostgreSQL + Drizzle
*   **Drizzle ORM:** Lựa chọn vì tốc độ thực thi cực nhanh, hỗ trợ TypeScript tuyệt đối và cho phép quản lý Schema một cách minh bạch qua `pgEnum`.
*   **Schema Design:** Tuân thủ mô hình **Single-Source-of-Truth** xoay quanh bảng `organizations`.

## 3. Communication & Jobs
*   **EventBus (Kafka/RabbitMQ):** Sử dụng để giao tiếp bất đồng bộ giữa các module (Choreography Pattern). Hiện tại đã triển khai `KafkaEventBusAdapter` làm adapter chính.
*   **BullMQ (Redis):** Xử lý các tác vụ nặng chạy ngầm (Background Jobs) như: Sinh PDF hóa đơn, Import hàng loạt dữ liệu Lead (2000+ records).

## 4. Frontend & Presentation
*   **Next.js (App Router):** Xây dựng giao diện hướng người dùng.
*   **Swagger/OpenAPI:** Tự động hóa tài liệu API, đảm bảo Frontend luôn nắm bắt được Schema mới nhất từ Backend.

## 5. Migration Tooling (26/04/2026)

Để di cư dữ liệu CRM legacy (CSV/XLSX) sang hệ thống mới, sử dụng:

*   **`csv-parse`**: Parse file CSV legacy có header vỡ, multi-line, relax_quotes. Mapping theo chỉ số cột thay vì tên cột.
*   **`ts-node` standalone scripts**: Các script di cư chạy độc lập, tái sử dụng NestJS DI context nhưng không khởi chạy HTTP server.
*   **Hybrid Storage (JSONB)**: Cột `metadata JSONB` trên các bảng chính để lưu dữ liệu legacy không có cột riêng. Chi tiết xem **ADR 003** trong `architecture.md`.

---
*Cập nhật ngày 30/04/2026 bởi Antigravity AI.*
