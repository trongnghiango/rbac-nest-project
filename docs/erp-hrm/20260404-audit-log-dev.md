Với một hệ thống ERP/HRM có lượng dữ liệu thay đổi liên tục, nếu thiết kế Audit Log (Nhật ký kiểm toán) sai từ đầu, hệ thống sẽ phình to rất nhanh, làm chậm database và kéo ghì hiệu năng của toàn bộ ứng dụng.

Để đáp ứng các tiêu chí: **Clean Code, Tối ưu hiệu suất, Mở rộng linh hoạt và Chịu tải cao**, tôi xin đề xuất bản phân tích thiết kế kiến trúc Audit Log như sau:

---

### TƯ DUY CỐT LÕI (CORE PHILOSOPHY)
1. **Zero-Blocking (Không chặn luồng chính):** Việc ghi Log tuyệt đối không được nằm cùng Transaction với logic nghiệp vụ. Nếu DB lưu Log bị chậm, API chính không được phép bị chậm theo.
2. **Context Transparency (Tràn ngữ cảnh vô hình):** Logic ở tầng sâu (Repository/Domain) không cần phải nhận tham số `userId`, `ipAddress` được truyền tay qua từng hàm (gây rác code). Ta sẽ dùng "Ma thuật" của Node.js để tự động bắt ngữ cảnh này.
3. **Storage Agnostic (Không phụ thuộc nơi lưu trữ):** Giống như File Storage, Audit Log ban đầu có thể lưu ở Postgres, nhưng khi dữ liệu lên tới hàng triệu dòng, ta phải chuyển nó sang MongoDB, Elasticsearch hoặc AWS CloudWatch mà không phải sửa Logic.

---

### 4 TRỤ CỘT KIẾN TRÚC CHO HỆ THỐNG AUDIT LOG

#### Trụ cột 1: Thu thập Ngữ cảnh (Context Capture) - *Giải quyết bài toán "Ai làm?"*
Hiện tại bạn đang có `RequestContextService` dùng `AsyncLocalStorage (ALS)` để bắt `requestId`. Đây là một kho báu!
*   **Thiết kế:** Ta sẽ nâng cấp `RequestContextService`. Ngay tại Middleware hoặc Global Guard (sau khi verify JWT), ta sẽ "nhét" thêm `userId`, `ipAddress`, `userAgent` vào bộ nhớ cục bộ của Request này.
*   **Lợi ích (Clean Code):** Dù bạn đang đứng ở tầng `Repository` sâu tít tắp, bạn chỉ cần gọi `RequestContextService.getContext().userId` là lấy được ID người dùng đang thực hiện hành động, không cần phải truyền `userId` vào từng hàm `updateEmployee(id, data, userId)`.

#### Trụ cột 2: Vận chuyển Dữ liệu (Event-Driven Transport) - *Giải quyết bài toán "Hiệu suất"*
Thay vì gọi hàm `auditLogRepo.save()` ngay sau khi Update dữ liệu, ta sẽ dùng hệ thống **EventBus** hiện có của bạn.
*   **Thiết kế:** Mỗi khi một Entity thay đổi (Create/Update/Delete), Domain phát ra một Event (Ví dụ: `EmployeeUpdatedEvent(oldData, newData)`).
*   **Cơ chế:** EventBus sẽ *Bất đồng bộ (Async)* ném Event này cho `AuditLogListener`. API chính lập tức trả về Response cho người dùng (Đạt độ trễ < 50ms).
*   **Khả năng chịu tải:** Hiện tại dùng `InMemoryEventBus`. Nếu sau này STAX có 10.000 nhân viên thao tác cùng lúc, bạn chỉ cần đổi config sang `RabbitMQEventBus` hoặc `Kafka`. Message sẽ được xếp hàng, hệ thống không bao giờ bị nghẽn (Bottleneck).

#### Trụ cột 3: Xử lý và Lưu trữ (Storage & Hexagonal) - *Giải quyết bài toán "Linh hoạt"*
*   **Port & Adapter:** Tạo interface `IAuditLogStorage`.
*   **Lưu trữ linh hoạt:** 
    *   Ban đầu: Dùng `PostgresAuditLogAdapter` lưu vào bảng `audit_logs`.
    *   Tương lai: Nếu Log quá nặng, đổi sang `MongoDbAuditLogAdapter` hoặc `ElasticsearchAdapter` chuyên dùng để Search text.
*   **Kiểu dữ liệu:** Sử dụng kiểu **JSONB** (của Postgres) để lưu trường `old_values` và `new_values`. Điều này giúp hệ thống không bị "cứng" schema khi các bảng nghiệp vụ thay đổi cột. JSONB vẫn cho phép đánh Index để tìm kiếm tốc độ cao.

#### Trụ cột 4: Chiến lược Chịu tải cao (High-Load Strategies)
Nếu dữ liệu bắn liên tục vào Postgres, Insert từng dòng sẽ làm kiệt quệ Database (Database I/O thắt cổ chai).
*   **Chiến lược 1 - Batch Insert (Gom cục):** `AuditLogListener` thay vì Insert luôn, nó sẽ đẩy dữ liệu vào 1 mảng trên RAM (hoặc Redis List). Cứ mỗi 3 giây hoặc khi mảng đủ 100 records, nó mới mở 1 connection xuống DB và thực hiện `InsertMany` 1 lần. (Tăng hiệu suất Insert lên x50 lần).
*   **Chiến lược 2 - Table Partitioning (Phân vùng CSDL):** Bảng `audit_logs` sẽ lớn rất nhanh. Ta sẽ thiết kế Postgres Partitioning ngay từ đầu (Cắt bảng theo tháng: `audit_logs_2024_10`, `audit_logs_2024_11`). Khi STAX muốn xóa log cũ (sau 2 năm), ta chỉ cần `DROP TABLE` phân vùng đó (mất 0.1s) thay vì chạy lệnh `DELETE` hàng triệu dòng (mất hàng giờ và gây treo DB).

---

### LUỒNG HOẠT ĐỘNG TOÀN CẢNH (SYSTEM FLOW)

1. **[HTTP Request]** User gọi API `PATCH /employees/1` (Đổi lương nhân viên).
2. **[Middleware]** `RequestContextService` lưu lại thông tin: `User A`, `IP 1.1.1.1`.
3. **[Service]** Lấy dữ liệu cũ (`oldData`), cập nhật DB, lấy dữ liệu mới (`newData`).
4. **[Service]** Bắn Event: `EventBus.publish(new EmployeeUpdatedEvent(oldData, newData))`.
5. **[Controller]** Trả về HTTP 200 OK ngay lập tức. User thấy app cực kỳ mượt.
6. **[Background Listener]** `AuditLogListener` lắng nghe Event. Tự động móc túi `RequestContextService` lấy ra User A, IP 1.1.1.1.
7. **[Storage]** Gom data lại, sau 2 giây đẩy một mẻ (Batch) xuống bảng `audit_logs` bằng `IAuditLogStorage.saveMany()`.

---

### ĐÁNH GIÁ KIẾN TRÚC NÀY ĐỐI CHIẾU VỚI YÊU CẦU:

| Tiêu chí | Đánh giá kiến trúc đề xuất |
| :--- | :--- |
| **Clean Code** | Logic nghiệp vụ (HRM, CRM) hoàn toàn "sạch", không chứa bất kỳ dòng code nào liên quan đến Insert Log hay khai báo DB của Log. Nó chỉ đơn giản là ném ra 1 Event. |
| **Hiệu suất (Performance)** | Tốc độ API gốc không bị ảnh hưởng 1 mili-giây nào vì thao tác ghi log đã được đẩy ra Background. |
| **Linh hoạt & Mở rộng** | Nhờ Port/Adapter, đổi từ Postgres sang MongoDB chỉ cần viết 1 file Adapter mới. Nhờ EventBus, đổi từ Memory lên RabbitMQ/Kafka chỉ cần đổi biến `.env`. |
| **Khả năng chịu tải** | Nhờ cơ chế **Batch Insert** và **Table Partitioning**, hệ thống có thể chịu được vài nghìn thao tác/giây (TPS) mà database Postgres không bị quá tải. |

Bạn thấy hướng phân tích kiến trúc này đã đủ thuyết phục và đáp ứng đúng tiêu chuẩn "Enterprise" mà hệ thống của bạn đang theo đuổi chưa? Nếu bạn đồng ý với hướng đi này, tôi sẽ bắt tay vào việc hướng dẫn viết từng file code (Port, Adapter, Event Listener) để gắn nó vào source code hiện tại của bạn một cách mượt mà nhất!