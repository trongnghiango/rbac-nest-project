Việc dừng lại một nhịp để nhìn toàn cảnh (Big Picture) bằng sơ đồ là một thói quen cực kỳ tuyệt vời của các Software Architect. Nó giúp bạn không bị "lạc lối" khi code ngày càng phình to.

Hệ thống bạn đang xây dựng là sự giao thoa giữa **HRM (Nhân sự)**, **CRM (Khách hàng)** và **Accounting (Tài chính)**. 

Tôi đã chuẩn bị **3 Sơ đồ Mermaid** thể hiện 3 góc nhìn quan trọng nhất của hệ thống hiện tại. Bạn có thể copy các khối code dưới đây dán vào [Mermaid Live Editor](https://mermaid.live/) hoặc xem trực tiếp trên các Markdown Viewer hỗ trợ Mermaid.

---

### Sơ đồ 1: Góc nhìn Kiến trúc (Clean Architecture)
Sơ đồ này cho thấy cách các Layer (Tầng) giao tiếp với nhau. Quy tắc bất di bất dịch: **Tầng ngoài (Controller/Drizzle) gọi vào tầng trong (Service/Domain), không có chiều ngược lại.**

```mermaid
graph TD
    subgraph "1. PRESENTATION LAYER (Giao tiếp với Client)"
        API[Client / Swagger / Postman]
        Controller[FinoteController]
    end

    subgraph "2. APPLICATION LAYER (Luồng nghiệp vụ)"
        FinoteSvc[FinoteService]
        SeqSvc[SequenceGeneratorService]
        TxManager[ITransactionManager]
    end

    subgraph "3. DOMAIN LAYER (Cốt lõi / Interfaces)"
        ISeqRepo((ISequenceRepository))
        FinoteEntity((Finote Entity / DTOs))
    end

    subgraph "4. INFRASTRUCTURE LAYER (Công nghệ cụ thể)"
        DrizzleTx[DrizzleTransactionManager]
        DrizzleSeqRepo[DrizzleSequenceRepository]
        DB[(PostgreSQL DB)]
    end

    %% Luồng đi của dữ liệu
    API -->|POST /finotes| Controller
    Controller -->|DTO| FinoteSvc
    
    FinoteSvc -->|1. Bắt đầu Transaction| TxManager
    TxManager -.->|Implement| DrizzleTx
    DrizzleTx --> DB

    FinoteSvc -->|2. Xin cấp mã| SeqSvc
    SeqSvc -->|3. Gọi Interface| ISeqRepo
    ISeqRepo -.->|Implement| DrizzleSeqRepo
    DrizzleSeqRepo -->|INSERT ON CONFLICT| DB

    %% Style
    classDef domain fill:#f9f,stroke:#333,stroke-width:2px;
    class ISeqRepo,FinoteEntity domain;
```

---

### Sơ đồ 2: Góc nhìn Luồng dữ liệu (Sequence Diagram)
Sơ đồ này mô tả chính xác những gì xảy ra bên dưới hàm `createFinote` mà chúng ta vừa viết. Nó giải thích cách chúng ta chống lỗi trùng mã (Race Condition).

```mermaid
sequenceDiagram
    autonumber
    actor User as Kế toán / Sale
    participant API as FinoteController
    participant Svc as FinoteService
    participant Tx as TxManager (Drizzle)
    participant Seq as SequenceGenerator
    participant DB as PostgreSQL

    User->>API: Gửi data {type: INCOME, amount: 15tr, orgId: 1}
    API->>Svc: createFinote(dto)
    
    Svc->>Tx: runInTransaction()
    activate Tx
    Tx->>DB: BEGIN TRANSACTION
    
    Svc->>Seq: generateCode('INC', tx)
    activate Seq
    Seq->>DB: INSERT ... ON CONFLICT DO UPDATE (Khóa dòng)
    Note right of DB: DB khóa dòng 'INC-2026'.<br/>Các request khác phải chờ.
    DB-->>Seq: Trả về số currentValue (VD: 1)
    Seq-->>Svc: Format thành 'INC-2026-0001'
    deactivate Seq

    Svc->>DB: INSERT INTO finotes (code, amount...)
    DB-->>Svc: Trả về Finote record
    
    Tx->>DB: COMMIT TRANSACTION
    deactivate Tx
    
    Svc-->>API: Trả về kết quả Thành công
    API-->>User: Hiển thị Hóa đơn INC-2026-0001
```

---

### Sơ đồ 3: Góc nhìn Cơ sở dữ liệu (Entity Relationship - ERD)
Sơ đồ này thể hiện **Trái tim của hệ thống ERP**. Nó cho thấy bảng `finotes` (Nguyên tử tài chính) đứng ở giữa và liên kết toàn bộ công ty (Nhân sự) với thế giới bên ngoài (Khách hàng).

```mermaid
erDiagram
    ORGANIZATIONS ||--o{ FINOTES : "Phải trả tiền (INCOME)"
    EMPLOYEES ||--o{ FINOTES : "Tạo phiếu / Duyệt phiếu (EXPENSE)"
    FINOTES ||--o{ FINOTE_PAYMENTS : "Được thanh toán qua"
    FINOTES ||--o{ FINOTE_ATTACHMENTS : "Có chứng từ đính kèm"

    SYSTEM_SEQUENCES {
        string prefix PK "Vd: INC-2026"
        int current_value "Vd: 15"
        timestamp updated_at
    }

    FINOTES {
        int id PK
        string code UK "Vd: INC-2026-0001"
        string type "INCOME / EXPENSE"
        int source_org_id FK "Trỏ tới Khách hàng"
        int requested_by_id FK "Trỏ tới Nhân viên"
        numeric amount "Tổng tiền cần thu/chi"
        numeric paid_amount "Tổng tiền ĐÃ thu/chi"
        string status "PENDING / PAID / ..."
        timestamp deadline_at 
    }

    FINOTE_PAYMENTS {
        int id PK
        int finote_id FK
        numeric amount "Số tiền giao dịch lần này"
        string payment_method "BANK / CASH"
        int recorded_by_id FK "Kế toán xác nhận"
        timestamp payment_date
    }

    ORGANIZATIONS {
        int id PK
        string company_name
        string status
    }

    EMPLOYEES {
        int id PK
        string employee_code
        string full_name
    }
```

### Tóm tắt vị trí hiện tại của bạn:
1. Bạn đã có một **Nền tảng Database (ERD)** cực kỳ vững chắc để scale lên thành ERP.
2. Bạn đã dựng xong **Kiến trúc Clean (Architecture)** để tách biệt các lớp, code rất dễ bảo trì.
3. Bạn vừa hoàn thành **Luồng sinh mã an toàn (Sequence Workflow)** cho module Tài chính.

Nhìn vào các sơ đồ trên, bạn muốn chúng ta đắp "thịt" cho phần nào tiếp theo?
1. Viết `FinoteController` để test API tạo phiếu qua Postman.
2. Bắt đầu xử lý EventBus (Để khi tạo phiếu xong thì tự động sinh file PDF).
