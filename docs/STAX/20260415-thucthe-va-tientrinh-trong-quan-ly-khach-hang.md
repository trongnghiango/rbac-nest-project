Ap dụng mô hình **360-Degree View** (Cái nhìn toàn diện) thường thấy trong các hệ thống CRM quốc tế như Salesforce hoặc Microsoft Dynamics.

Cách tiếp cận này không tách rời bảng (`table`) theo kiểu "người này là Lead, người kia là Client", mà tách theo **"Thực thể" (Entity)** và **"Tiến trình" (Process)**.

---

### 1. Kiến trúc tổng thể (4 Lớp)

1.  **Lớp Định danh (Organizations va Contacts):** Lưu giữ "Họ là ai?". - Liên hệ và Thêm Khách hàng (nhưng chưa ở trạng thái ACTIVE) 
2.  **Lớp Chém gió/Bán hàng (Leads/Opportunities):** Lưu giữ "Họ muốn mua gì và đang ở bước nào?". - Tư vấn lôi kéo để trở thành khách hàng thực sự.
3.  **Lớp Dịch vụ (Contracts):** Lưu giữ "Họ đã ký gì và phí bao nhiêu?". - Chốt hợp đồng có tiền -> tự động ACTIVE.
4.  **Lớp Vận hành (Service Teams):** Lưu giữ "Ai đang phục vụ họ?". -> Sau ky hop dong sẽ có nhân viên hỗ trợ.

---

### 2. Chi tiết Schema (DB)

#### A. Bảng Organizations (Thực thể gốc)
Đây là bảng trung tâm. Một "Anh Long" hay "Công ty TNHH" đều nằm ở đây.

```typescript
// src/database/schema/crm/organizations.schema.ts
export const organizations = pgTable('organizations', {
  id: serial('id').primaryKey(),
  name: text('name').notNull(),         // Lúc đầu là "Anh Long", sau này là "Công ty TNHH Long"
  tax_code: text('tax_code').unique(),  // Nullable cho đến khi thành lập xong
  type: text('type').default('INDIVIDUAL'), // INDIVIDUAL | ENTERPRISE
  
  // Thông tin liên hệ chính
  main_contact_phone: text('main_contact_phone'),
  main_contact_email: text('main_contact_email'),
  address: text('address'),

  status: text('status').default('PROSPECT'), // PROSPECT (Tiềm năng) | ACTIVE (Đang phục vụ) | INACTIVE
  created_at: timestamp('created_at').defaultNow(),
});
```

#### B. Bảng Leads (Tiến trình bán hàng)
Một Organization có thể có nhiều Leads (hôm nay hỏi Thành lập, tháng sau hỏi Kế toán).

```typescript
// src/database/schema/crm/leads.schema.ts
export const leads = pgTable('leads', {
  id: serial('id').primaryKey(),
  organization_id: integer('organization_id').references(() => organizations.id),
  
  title: text('title').notNull(),        // "Tư vấn báo cáo thuế"
  source: text('source'),                // Relationship, Facebook, Web...
  service_demand: text('service_demand'),// Nhu cầu dịch vụ
  
  assigned_to_id: integer('assigned_to_id').references(() => employees.id), // Tư vấn viên (Sales)
  
  stage: text('stage').default('NEW'),   // NEW | CONSULTING | NEGOTIATING | WON | LOST
  
  notes: text('notes'),                  // Ghi chú (Sợ chứng từ, sợ phiền...)
  created_at: timestamp('created_at').defaultNow(),
});
```

#### C. Bảng Contracts (Kết quả sau khi WON)
Khi Lead chuyển sang `WON`, thông tin hợp đồng sẽ được đổ vào đây.

```typescript
// src/database/schema/crm/contracts.schema.ts
export const contracts = pgTable('contracts', {
  id: serial('id').primaryKey(),
  organization_id: integer('organization_id').references(() => organizations.id),
  lead_id: integer('lead_id').references(() => leads.id), // Link về Lead gốc

  contract_number: text('contract_number').unique(),
  signed_at: date('signed_at'),
  
  billing_cycle: text('billing_cycle'), // Quý / Tháng
  fee_amount: numeric('fee_amount', { precision: 15, scale: 2 }),
  
  status: text('status').default('ACTIVE'), // ACTIVE | SUSPENDED | TERMINATED
});
```

#### D. Bảng Service Assignments (Đội ngũ phục vụ)
Đây là nơi giải quyết các cột: *Trưởng phòng, Leader, Chuyên viên, Trợ lý*.

```typescript
// src/database/schema/crm/service_assignments.schema.ts
export const serviceAssignments = pgTable('service_assignments', {
  id: serial('id').primaryKey(),
  organization_id: integer('organization_id').references(() => organizations.id),
  employee_id: integer('employee_id').references(() => employees.id),
  
  // Vai trò cụ thể (Mapping từ file Excel của bạn)
  role: text('role'), 
  // TRUONG_PHONG | LEADER | CHUYEN_VIEN_B2 | CHUYEN_VIEN_B1 | TRO_LY_A2 | TRO_LY_A1
  
  assigned_at: timestamp('assigned_at').defaultNow(),
});
```

---

### 3. Tại sao cách này là "Chuyên nghiệp nhất"?

1.  **Tính kế thừa:** Khi "Anh Phong" chưa có công ty, anh liên hệ và chỉ lưu giữ `Organization` (name: Anh Long) và `Lead`. Khi anh ấy thành lập công ty, bạn chỉ cần **Update** bảng `Organization` (name: Công ty ABC, tax_code: 031...) chứ không phải xóa đi tạo lại hay copy dữ liệu sang bảng khác.
2.  **Quản lý đa dịch vụ:** Một khách hàng (Organization) có thể sẽ có nhiều `Lead` có thể gồm có 1 Hợp đồng thành lập công ty, 1 hợp đồng Thuế, 1 hợp đồng BHXH. Cách này cho phép quản lý nhiều hợp đồng trên cùng một thực thể khách hàng.
3.  **Báo cáo cực ok con dê:**
    *   Có thể thống kê: "Tỷ lệ chuyển đổi từ `Lead` cá nhân sang `Doanh nghiệp` là bao nhiêu %?".
    *   Xem: "Trong 3 nhân sự (my staff) phục vụ khách hàng này, ai là người được gán gần nhất?".
4.  **Lịch sử xuyên suốt:** Toàn bộ ghi chú "Sợ chứng từ", "Sợ cơ quan ban ngành" từ lúc là Lead vẫn được giữ nguyên trong hồ sơ `Organization` để nhân viên kế toán sau này biết cách cư xử khéo léo với khách.

---

### 4. Luồng xử lý code (Service Logic)

*   **Khi tạo Lead mới:** 
    1. Kiểm tra SĐT đã có trong `Organizations` chưa? 
    2. Nếu chưa -> Tạo `Organization` + Tạo `Lead`.
    3. Nếu rồi -> Chỉ tạo `Lead` mới cho `Organization` cũ.
*   **Khi chốt Hợp đồng (WON):** 
    1. Update `Lead.stage = 'WON'`.
    2. Update `Organization.status = 'ACTIVE'`.
    3. Tạo `Contract`.
    4. Tạo 6 bản ghi trong `serviceAssignments` (Trưởng phòng -> Trợ lý).

**Đây chính là cách các hệ thống ERP và CRM lớn vận hành.** Nếu bạn triển khai theo hướng này, dự án của bạn sẽ có khả năng mở rộng (Scalability) cực kỳ tốt cho giai đoạn 2, 3 của STax.

Bạn có muốn tôi viết mẫu **Drizzle Query** để lấy ra toàn bộ thông tin của một khách hàng bao gồm: *Tên, Phí dịch vụ, và danh sách 6 nhân sự đang phục vụ họ* không?


> Thế nào là thực thể Entity?
>  