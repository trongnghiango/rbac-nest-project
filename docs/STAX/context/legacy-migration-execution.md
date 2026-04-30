# BÁO CÁO DI CƯ DỮ LIỆU LEGACY CRM → STAX

**Ngày thực hiện:** 26/04/2026  
**Môi trường:** Development / Test DB  
**Người thực hiện:** AI Agent (Antigravity) + Developer  
**Trạng thái:** ✅ HOÀN THÀNH TOÀN BỘ

---

## 1. TỔNG QUAN PIPELINE

Dữ liệu CRM di chuyển theo một luồng thác nước chặt chẽ nhằm bảo đảm toàn vẹn quan hệ khóa ngoại:

```
Employees (HR) 
    ↓
Organizations + Contacts   ← Clients.csv
    ↓
Leads                      ← Lead.csv
    ↓
Contracts                  ← Tổng hợp từ Organizations.metadata
    ↓
Finotes + FinoteItems      ← FN.2026.csv
```

### Kết quả tổng thể

| Phase | Nguồn dữ liệu | Records Tạo Mới | Tỷ lệ lỗi |
|-------|--------------|-----------------|------------|
| **0 - Employees** | `03_core_employees.csv` | ~30 nhân viên | 0% |
| **1 - Clients** | `2026.STAX.CRM.Clients.csv` | **202 Organizations** + 202 Contacts | 4.3% (duplicate email) |
| **2 - Leads** | `2026.STAX.CRM.Lead.csv` | **1,172 Leads** | 0% |
| **3 - Contracts** | Tổng hợp từ metadata | **158 Hợp đồng** | 0% |
| **4 - Finotes** | `04_.STAX.CRM.FN.2026.csv` | **363 Phiếu + multi-items** | 0% |

---

## 2. THIẾT KẾ KIẾN TRÚC: HYBRID STORAGE PATTERN

### Vấn đề ban đầu
File CSV legacy chứa nhiều cột không có trong schema quan hệ mới (ví dụ: `Nick name`, `Thời gian làm việc`, `Số hợp đồng`, `Tình trạng tạm ngưng`, `Ghi chú nội bộ`). Nếu bỏ qua, mất thông tin kinh doanh quan trọng. Nếu thêm cột vào schema chính, vi phạm nguyên tắc **Single Responsibility** và làm bloat schema.

### Giải pháp: Hybrid Storage (JSONB)
Thêm cột `metadata JSONB` vào các bảng:
- `organizations.metadata` — lưu `contractNo, feeType, expectedFee, suspendDeadline, serviceDesc, original_status`
- `contacts.metadata` — lưu `legal_representative`
- `leads.metadata` — lưu `legacy_date, original_status, original_consultant, raw_phone`
- `contracts.metadata` — lưu `legacy_sign_date, source, suspend_deadline`

**Lợi ích:** Dữ liệu lịch sử không bị mất, schema chuẩn không bị ô nhiễm, có thể query JSONB khi cần.

---

## 3. CHI TIẾT TỪNG PHASE

### Phase 1 — Clients (Organizations + Contacts)

**File:** `2026.STAX.CRM.Clients.csv`

**Vướng mắc gặp phải:**

| # | Vấn đề | Nguyên nhân | Cách khắc phục |
|---|--------|-------------|----------------|
| 1 | Header CSV bị vỡ nhiều dòng (malformed) | File Excel export thô, có cell merge và newline trong header | Parse bằng `csv-parse` với `relax_quotes: true`, mapping theo **chỉ số cột** thay vì tên cột |
| 2 | 9 records bị lỗi `UNIQUE constraint (contacts.email)` | Nhiều công ty dùng chung email nhân viên (`haidangdo.lvg@gmail.com`) | Wrap từng record trong `try/catch`, ghi log, bỏ qua và tiếp tục — không dừng toàn bộ migration |
| 3 | Enum `lead_source` không chứa giá trị `"Zalo"` | Schema cũ không có | Thêm `ZALO` vào `leadSourceEnum`, chạy `drizzle-kit push` apply lên DB |
| 4 | Trạng thái tiếng Việt (`Thanh Lý HĐ`, `Chờ ký`) không map được | Dữ liệu legacy dùng chuỗi mô tả tự do | Viết hàm mapper dùng `toLowerCase().includes()` để phát hiện từ khóa |

**Kết quả:** 202 Organizations + 202 Contacts | 1 trùng lặp | 9 lỗi email trùng

---

### Phase 2 — Leads

**File:** `2026.STAX.CRM.Lead.csv`

**Vướng mắc gặp phải:**

| # | Vấn đề | Nguyên nhân | Cách khắc phục |
|---|--------|-------------|----------------|
| 1 | `TS2339: Property 'split' does not exist on type 'unknown'` | Drizzle ORM suy diễn kiểu `full_name` là `unknown` khi schema có cột `jsonb` | Cast tường minh: `const fullNameStr = e.full_name as string` |
| 2 | `TS2339: Property 'nicknames' does not exist on type 'unknown'` | Cùng lý do — `metadata` JSONB không có type inference | Cast: `const meta = e.metadata as any` |
| 3 | Không thể khớp consultant (nhân viên phụ trách) theo tên đầy đủ | Tên trong CSV là nickname ngắn (VD: `Trúc Đào`), tên trong DB là họ tên đầy đủ | Dùng kết hợp 3 chiến lược: match full_name contains, match nickname trong metadata, match họ cuối |
| 4 | Số điện thoại có ký tự không chuẩn (`+84`, dấu cách, `-`) | Nhập liệu tay không chuẩn hóa | Normalize với regex: `phone.replace(/[^0-9]/g, '')` |

**Kết quả:** 1,172 Leads | 0 lỗi | Tỷ lệ liên kết Org ~35% (các lead có phone trùng contacts)

---

### Phase 3 — Contracts (Tổng hợp)

**Chiến lược:** Không có file CSV Hợp đồng riêng. Tổng hợp từ `organizations.metadata` vì khi import Clients đã lưu `contractNo`, `feeType`, `expectedFee` vào JSONB.

**Vướng mắc gặp phải:**

| # | Vấn đề | Nguyên nhân | Cách khắc phục |
|---|--------|-------------|----------------|
| 1 | `TS2769: No overload matches this call` — `organization_id` type `unknown` | Drizzle không thể suy diễn kiểu `id` khi query có jsonb | Cast: `org.id as number` tại điểm gọi `.values({...})` |
| 2 | Thiếu cột `metadata` trong bảng `contracts` | Schema không có sẵn | Thêm `jsonb('metadata')` vào schema, chạy `drizzle-kit push` |
| 3 | Số tiền hợp đồng trong CSV có định dạng VN: `1.500.000` | Dấu chấm là phân cách hàng nghìn (không phải thập phân) | Strip tất cả ký tự phi số: `replace(/[^0-9]/g, '')` |

**Kết quả:** 158 Contracts tạo từ 207 Organizations (49 org không đủ dữ liệu HĐ bị bỏ qua đúng logic)

---

### Phase 4 — Finotes

**File:** `04_.STAX.CRM.FN.2026.csv`

**Vướng mắc gặp phải:**

| # | Vấn đề | Nguyên nhân | Cách khắc phục |
|---|--------|-------------|----------------|
| 1 | 1 FN code có nhiều dòng (multi-item) | Mỗi dịch vụ trong 1 phiếu chiếm 1 dòng CSV | **Group by FN code** trước, 1 group = 1 `finote` header + N `finote_items` |
| 2 | FN Hủy có `total_amount = 0` | Phiếu bị hủy ghi `0` vào cột số tiền | Filter bỏ qua item có `total <= 0`, nếu group không còn item hợp lệ thì bỏ qua cả FN |
| 3 | `requested_by_id` NOT NULL nhưng không có thông tin người tạo | CSV không ghi người tạo phiếu | Lấy nhân viên có ID nhỏ nhất (Director/Admin đầu tiên trong hệ thống) làm default |
| 4 | Ngày tháng format `DD/MM/YYYY` không parse được bởi `new Date()` | JS `Date()` mặc định nhận `YYYY-MM-DD` | Split thủ công và rebuild: `new Date(\`${y}-${m}-${d}\`)` |
| 5 | Dòng header tổng cộng (dòng 2 của CSV) bị tính vào data | CSV có dòng summary không có FN code | Filter chỉ giữ dòng có `r[3]` bắt đầu bằng `'FN'` |

**Kết quả:** 429 dòng → 365 nhóm FN → 363 Finotes tạo mới + toàn bộ FinoteItems | 2 FN Hủy bỏ qua | 0 lỗi

---

## 4. KẾ HOẠCH DI CƯ PRODUCTION

> [!CAUTION]
> Đây là kế hoạch cho môi trường **Production thực tế**. Cần thực hiện cẩn thận, có backup và rollback plan.

### 4.1 Checklist chuẩn bị trước khi migration

- [ ] **Backup toàn bộ DB Production** (pg_dump) trước khi bắt đầu
- [ ] **Chạy full migration trên staging** với file CSV thực và xác nhận kết quả
- [ ] **Dọn sạch dữ liệu Test** khỏi Production DB (nếu đã seed test data)
- [ ] **Thông báo downtime** cho người dùng (khuyến nghị thực hiện ngoài giờ làm việc)
- [ ] **Disable auto-seed** trong `DatabaseSeeder` để tránh conflict
- [ ] Xác nhận các file CSV/XLSX là **bản cuối cùng, đã được business approve**

### 4.2 Thứ tự thực thi trên Production

```bash
# Bước 0: Schema Migration (chỉ áp metadata columns nếu chưa có)
NODE_ENV=production npx drizzle-kit push

# Bước 1: Employees (phải có trước — FK required_by_id)
npx ts-node stax-full-migration.run.ts

# Bước 2: Organizations + Contacts (Clients)
npx ts-node crm-migration.run.ts

# Bước 3: Leads
npx ts-node crm-leads-migration.run.ts

# Bước 4: Contracts (Synthesize từ Organizations)
npx ts-node crm-contracts-migration.run.ts

# Bước 5: Finotes
npx ts-node crm-finotes-migration.run.ts
```

### 4.3 Xử lý dữ liệu sạch hơn cho Production

Khi có đủ thời gian chuẩn bị, nên thực hiện thêm các bước làm sạch data:

**a) Deduplicate email contacts:**
```sql
-- Tìm email trùng trước khi import
SELECT email, COUNT(*) FROM (SELECT email FROM csv_data) GROUP BY email HAVING COUNT(*) > 1;
```
Giải quyết bằng cách chỉ tạo 1 contact primary, liên kết các org còn lại bằng secondary contact.

**b) Chuẩn hóa số điện thoại:**
- Convert `0901234567` → `+84901234567` (E.164 format) để tránh false-negative khi lookup

**c) Fuzzy match Công ty:**
Dùng `pg_trgm` PostgreSQL extension để match tên công ty gần giống nhau thay vì `exact match`:
```sql
SELECT *, similarity(company_name, 'CÔNG TY TNHH ABC') AS score 
FROM organizations ORDER BY score DESC LIMIT 5;
```

**d) Mapping nhân viên phụ trách (PIC):**
Cần cung cấp thêm bảng mapping `Nick name ↔ Employee ID` dạng CSV nhỏ để tăng tỷ lệ resolve `assigned_to_id` trong Leads.

### 4.4 Xác minh sau migration

Chạy các query kiểm tra sau khi migration:

```sql
-- Kiểm tra Organizations không có Contact nào
SELECT o.company_name FROM organizations o 
LEFT JOIN contacts c ON c.organization_id = o.id 
WHERE c.id IS NULL AND o.id != 1;

-- Kiểm tra Finotes không link được Organization
SELECT code, title FROM finotes WHERE source_org_id IS NULL LIMIT 20;

-- Kiểm tra Leads không có org (lead orphan)
SELECT COUNT(*) FROM leads WHERE organization_id IS NULL;

-- Tổng tiền các Finotes theo trạng thái
SELECT status, COUNT(*), SUM(total_amount) 
FROM finotes GROUP BY status;

-- Kiểm tra FinoteItems đầy đủ
SELECT f.code, COUNT(fi.id) as item_count 
FROM finotes f LEFT JOIN finote_items fi ON fi.finote_id = f.id
GROUP BY f.code HAVING COUNT(fi.id) = 0;
```

### 4.5 Rollback Plan

Nếu phát hiện lỗi nghiêm trọng trong quá trình migration:

```bash
# Option A: Restore backup
pg_restore -d stax_prod backup_pre_migration.dump

# Option B: Xóa selective nếu chỉ 1 phase lỗi
# (Do migration scripts có deduplication, chạy lại an toàn)
TRUNCATE TABLE finotes CASCADE;
TRUNCATE TABLE leads CASCADE;
-- Rồi chạy lại script tương ứng
```

> [!NOTE]
> Các script migration đều có **idempotency** nhờ kiểm tra duplicate trước khi insert. Việc retry 1 phase cụ thể là **an toàn** và sẽ không tạo duplicate.

---

## 5. CÁC CẢI TIẾN CÓ THỂ TRONG TƯƠNG LAI

| Cải tiến | Mô tả | Mức độ ưu tiên |
|----------|-------|----------------|
| **Dry-run mode** | Thêm flag `--dry-run` để preview kết quả mà không ghi DB | Cao |
| **Progress logging** | Ghi log tiến độ vào file thay vì chỉ console để audit | Cao |
| **Fuzzy org matching** | Dùng `pg_trgm` để match tên công ty gần đúng, tăng tỷ lệ link Finote→Org | Trung bình |
| **Email dedup strategy** | Khi email trùng, tạo contact với email `null` + note trong metadata | Trung bình |
| **Staff mapping file** | File CSV riêng `nick_name,employee_id` để resolve 100% PIC trong Leads | Cao |
| **Idempotent CLI** | Đóng gói các script thành 1 CLI duy nhất: `migrate --phase=all --env=prod` | Thấp |

---

## 6. DANH SÁCH FILE TRIỂN KHAI

| File | Mục đích |
|------|----------|
| `src/modules/test/application/services/crm-legacy-migration.service.ts` | Service chứa toàn bộ logic migration (migrateClients, migrateLeads, synthesizeContracts, migrateFinotes) |
| `src/modules/test/application/scripts/crm-migration.run.ts` | Runner Phase 1 — Clients |
| `src/modules/test/application/scripts/crm-leads-migration.run.ts` | Runner Phase 2 — Leads |
| `src/modules/test/application/scripts/crm-contracts-migration.run.ts` | Runner Phase 3 — Contracts |
| `src/modules/test/application/scripts/crm-finotes-migration.run.ts` | Runner Phase 4 — Finotes |
| `src/database/schema/crm/organizations.schema.ts` | Đã thêm `metadata: jsonb` |
| `src/database/schema/crm/contacts.schema.ts` | Đã thêm `metadata: jsonb` |
| `src/database/schema/crm/leads.schema.ts` | Đã thêm `metadata: jsonb` + enum `ZALO` |
| `src/database/schema/crm/contracts.schema.ts` | Đã thêm `metadata: jsonb` |

---

> [!IMPORTANT]
> **Cập nhật bảo mật (30/04/2026):** Toàn bộ các mật khẩu mặc định sử dụng trong quá trình migration (`Stax@123`, `Company@2026`) đã được chuyển sang quản lý qua biến môi trường `SEED_DEFAULT_PASSWORD`. Tuyệt đối không hardcode mật khẩu vào source code hoặc scripts.

*Báo cáo được cập nhật lần cuối vào ngày 30/04/2026 bởi Antigravity AI.*
