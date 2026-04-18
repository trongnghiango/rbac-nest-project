Dưới đây là sơ đồ hóa toàn bộ quy trình vận hành từ lúc khách hàng là một cá nhân (Lead) cho đến khi trở thành Doanh nghiệp có nhiều hợp đồng và đội ngũ phục vụ chuyên nghiệp.

---

### 1. Sơ đồ Quan hệ Thực thể (ERD - Logic trung tâm)
Sơ đồ này thể hiện bảng `Organizations` là "trái tim" của hệ thống, kết nối mọi thông tin xuyên suốt vòng đời khách hàng.

```mermaid
erDiagram
    ORGANIZATIONS ||--o{ LEADS : "tạo cơ hội"
    ORGANIZATIONS ||--o{ CONTACTS : "có người liên hệ"
    ORGANIZATIONS ||--o{ CONTRACTS : "ký kết dịch vụ"
    ORGANIZATIONS ||--o{ SERVICE_ASSIGNMENTS : "được phục vụ bởi"
    EMPLOYEES ||--o{ LEADS : "tư vấn (Sales)"
    EMPLOYEES ||--o{ SERVICE_ASSIGNMENTS : "thực thi (Operation)"
    CONTRACTS ||--|| LEADS : "chuyển đổi từ"

    ORGANIZATIONS {
        int id PK
        string name "Tên/Nickname"
        string tax_code "MST (nullable)"
        string type "Individual/Enterprise"
        string status "Prospect/Active/Inactive"
    }

    LEADS {
        int id PK
        string service_demand "Nhu cầu"
        string stage "New/Won/Lost"
        string notes "Sợ pháp lý..."
    }

    CONTRACTS {
        int id PK
        string status "Active/Terminated"
        numeric monthly_fee
        string service_type "Kế toán/Hóa đơn"
    }

    SERVICE_ASSIGNMENTS {
        int id PK
        string role "Leader/Chuyên viên..."
    }
```

---

### 2. Quy trình Tiến hóa: Từ Cá nhân (Lead) sang Doanh nghiệp (Client)
Sơ đồ này mô tả cách hệ thống xử lý tình huống "Anh Phong" chưa có công ty, sau đó chốt hợp đồng và trở thành doanh nghiệp chính thức.

```mermaid
sequenceDiagram
    participant S as Sales (Employee)
    participant O as Organizations (Profile)
    participant L as Leads (Opportunity)
    participant C as Contracts (Service)
    participant Op as Operation Team

    Note over S, L: GIAI ĐOẠN TIỀN PHÁP NHÂN
    S->>O: Tạo hồ sơ: "Anh Phong" (Type: Individual)
    S->>L: Tạo Lead: "Thành lập công ty" (Stage: New)
    
    Note over S, L: CHỐT HỢP ĐỒNG THÀNH LẬP
    L->>L: Update Stage = WON
    L->>O: Update Status = ACTIVE_CUSTOMER
    L->>C: Tạo Hợp đồng 1: "Thành lập DN" (Status: Active)
    
    Note over O, C: SAU KHI CÓ MST
    O->>O: Update Name: "Công ty TNHH Phong" <br/> Update Type: Enterprise <br/> Fill Tax_code: 031xxx
    
    Note over S, C: GIAI ĐOẠN PHÁT SINH DỊCH VỤ MỚI
    S->>L: Tạo Lead 2: "Kế toán thuế trọn gói"
    L->>L: Update Stage = WON
    L->>C: Tạo Hợp đồng 2: "Kế toán" (Status: Active)
    L->>Op: Gán Team phục vụ: Leader, Chuyên viên, Trợ lý...
```

---

### 3. Logic xử lý Trạng thái (Multi-Contract Status)
Sơ đồ này giải thích câu hỏi của bạn: "Nếu làm 2 hợp đồng, ngưng 1 thì Global Status của khách hàng sẽ ra sao?".

```mermaid
flowchart TD
    Start([Sự kiện: Thay đổi trạng thái Hợp đồng]) --> CheckID[Xác định Organization ID]
    CheckID --> CountActive{Đếm số lượng Contract <br/> có status = 'ACTIVE' <br/> của Organization này}
    
    CountActive -- "Số lượng > 0" --> Active[Organization.status = 'ACTIVE']
    CountActive -- "Số lượng = 0" --> CheckHistory{Kiểm tra lịch sử}
    
    Active --> End([Kết thúc: Khách hàng vẫn đang sử dụng dịch vụ])
    
    CheckHistory -- "Tất cả đều Thanh lý" --> Churned[Organization.status = 'CHURNED']
    CheckHistory -- "Có HĐ Tạm ngưng" --> Suspended[Organization.status = 'SUSPENDED']
    
    Churned --> End2([Kết thúc: Khách hàng đã rời bỏ])
    Suspended --> End3([Kết thúc: Chờ khách quay lại])

    style Active fill:#4CAF50,stroke:#333,stroke-width:2px,color:#fff
    style Churned fill:#F44336,stroke:#333,stroke-width:2px,color:#fff
    style Suspended fill:#FF9800,stroke:#333,stroke-width:2px,color:#fff
```

---

### Sự "Hoàn hảo" ở đây nằm ở 3 điểm:

1.  **Dữ liệu không bao giờ bị ngắt quãng:** Bạn thấy toàn bộ hành trình từ lúc "Anh Phong" còn sợ pháp lý cho đến khi "Công ty TNHH Phong" có 5 hợp đồng. Không có dữ liệu nào bị xóa hay copy sang bảng khác.
2.  **Quản lý Ma trận Phục vụ (6 người):** Bảng `Service_Assignments` cho phép bạn quản lý cực kỳ linh hoạt. Nếu Chuyên viên B2 nghỉ việc, bạn chỉ cần Update 1 dòng trong bảng này, tất cả khách hàng của người đó sẽ được chuyển sang người mới mà không ảnh hưởng đến Hợp đồng hay Hồ sơ gốc.
3.  **Tối ưu báo cáo Tài chính:** Bạn có thể query ra: *"Trong tháng 6, STax thu bao nhiêu tiền từ các khách hàng có gốc từ nguồn Relationship?"* (Kết nối từ `Contracts` -> `Leads` -> `Organizations`). Đây là báo cáo mà các hệ thống tách bảng thông thường rất khó làm được.

Bạn có muốn tôi giúp bạn chuyển hóa các sơ đồ này thành **Mẫu Class (Service Layer)** trong NestJS để hiện thực hóa logic này không?