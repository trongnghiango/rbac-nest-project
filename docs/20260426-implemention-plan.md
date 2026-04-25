# Kế Hoạch Thiết Kế AuditLog — STAX Enterprise

## Phân tích hiện trạng

Codebase hiện có:
- **`LoggingModule`**: Chỉ là **application logger** (Winston → console/file). Không phải AuditLog.
- **`IEventBus`** + **`IDomainEvent`**: Đã có cơ chế publish/subscribe event — đây là bệ phóng hoàn hảo.
- **`ILogger` Port**: Interface sạch, injected toàn hệ thống.
- **`transform-response.interceptor.ts`**: Có 1 interceptor ở tầng `core/interceptors` — chứng tỏ pattern này đã được dùng.
- **Không có bảng `audit_logs` nào** trong schema hiện tại.
- **Không có AuditInterceptor / AuditDecorator** nào.

---

## Phân tích & Đánh giá Chiến lược

### ❌ Cách sai: Gọi audit service trực tiếp trong mỗi use-case

```typescript
// ❌ BAD — Coupling cao, phải sửa mọi nơi khi audit thay đổi
async createLead(dto) {
    const lead = await this.leadRepo.save(dto);
    await this.auditService.log('LEAD_CREATED', lead); // <- tight coupling
    return lead;
}
```

**Vấn đề:** Vi phạm Single Responsibility, audit logic rải khắp codebase, khó scale, khó test, khó tắt/bật.

---

### ✅ Chiến lược đề xuất: 3-Layer AuditLog Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  LAYER 1: CAPTURE (Thu thập)                                │
│  AuditInterceptor (HTTP) + DomainEventHandler (Domain)      │
│  → Cả hai đều emit sang LAYER 2                             │
├──────────────────────────────────────────────────────────────┤
│  LAYER 2: PROCESS (Xử lý bất đồng bộ)                      │
│  AuditEventHandler ← IEventBus (BullMQ/in-process)         │
│  → Validate, enrich, route sang LAYER 3                     │
├──────────────────────────────────────────────────────────────┤
│  LAYER 3: STORE (Lưu trữ phân tầng)                        │
│  HOT  : PostgreSQL audit_logs (30 ngày gần nhất)           │
│  WARM : TimescaleDB / partitioned table (1 năm)             │
│  COLD : S3 / file (archive, compliance)                     │
└──────────────────────────────────────────────────────────────┘
```

---

## Kiến trúc chi tiết

### 1. Database Schema — `audit_logs`

Đặt trong `src/database/schema/system/audit-logs.schema.ts`:

```typescript
// Cần có: actor, action, resource, change snapshot, context
export const auditLogs = pgTable('audit_logs', {
    id:           bigserial('id', { mode: 'number' }).primaryKey(),
    // WHO
    actor_id:     integer('actor_id'),           // employee/user ID (null = system)
    actor_type:   varchar('actor_type', { length: 20 }).default('USER'),
    actor_ip:     varchar('actor_ip', { length: 45 }),
    // WHAT
    action:       varchar('action', { length: 100 }).notNull(), // e.g. 'LEAD.STAGE_CHANGED'
    resource:     varchar('resource', { length: 50 }).notNull(),// e.g. 'leads'
    resource_id:  varchar('resource_id', { length: 50 }),       // e.g. '123'
    // CHANGE SNAPSHOT
    before:       jsonb('before'),               // state trước khi thay đổi
    after:        jsonb('after'),                // state sau khi thay đổi
    // CONTEXT
    request_id:   varchar('request_id', { length: 50 }),
    user_agent:   text('user_agent'),
    metadata:     jsonb('metadata'),             // extra context tùy action
    severity:     varchar('severity', { length: 10 }).default('INFO'), // INFO|WARN|CRITICAL
    // WHEN
    created_at:   timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
},
(t) => ({
    actor_idx:    index('idx_audit_actor').on(t.actor_id),
    resource_idx: index('idx_audit_resource').on(t.resource, t.resource_id),
    created_idx:  index('idx_audit_created').on(t.created_at),
    action_idx:   index('idx_audit_action').on(t.action),
}));
```

**Thiết kế quan trọng:**
- **KHÔNG có FK** tới `users` hay `employees` — audit log phải tồn tại độc lập, dù actor bị xóa.
- **`bigserial`** thay vì `serial` — chuẩn bị cho hàng triệu records.
- **`before/after` JSONB** — lưu diff thay vì full object để tối ưu storage.
- **Partition by date** (PostgreSQL native) cho việc archive/purge.

---

### 2. Domain Layer — AuditableEvent Interface

```
src/core/shared/domain/events/auditable-event.interface.ts
```

```typescript
export interface IAuditableEvent extends IDomainEvent {
    // Nếu event implement interface này → tự động được ghi audit
    toAuditEntry(): AuditEntryDto;
}
```

Các domain event hiện có chỉ cần implement thêm `toAuditEntry()`. Giữ nguyên `IDomainEvent`, không breaking.

---

### 3. Application Layer — AuditLog Port

```
src/core/shared/application/ports/audit-log.port.ts
```

```typescript
export const AUDIT_LOG_PORT = 'IAuditLogService';

export interface IAuditLogService {
    log(entry: AuditEntryDto): Promise<void>;
    logBatch(entries: AuditEntryDto[]): Promise<void>;
    query(filter: AuditQueryDto): Promise<PaginatedResult<AuditLogRecord>>;
}
```

**Tương tự pattern `ILogger`** — module nào muốn inject audit chỉ cần dùng token.

---

### 4. Capture Layer — 2 điểm thu thập

#### 4a. HTTP Interceptor (tầng Infrastructure)

```
src/core/interceptors/audit.interceptor.ts
```

```typescript
@Injectable()
export class AuditInterceptor implements NestInterceptor {
    // Tự động capture: actor_id từ JWT, method, url, resource, resource_id từ route params
    // Emit AuditHttpEvent → IEventBus (ASYNC)
    // Không block response — fire & forget
}
```

Áp dụng **Global** hoặc **Per-controller** via `@UseInterceptors(AuditInterceptor)`.

#### 4b. Domain Event Handler (tầng Application)

```
src/modules/audit-log/application/handlers/audit-domain-event.handler.ts
```

```typescript
// Subscribe tất cả IAuditableEvent từ IEventBus
// Ghi vào DB với đầy đủ business context (before/after state)
```

---

### 5. Module Structure — `audit-log` (Tier 1 — Foundation)

```
src/modules/audit-log/
├── audit-log.module.ts          (Global, export AUDIT_LOG_PORT)
├── domain/
│   └── audit-log.entity.ts
├── application/
│   ├── ports/
│   │   └── audit-log-repository.port.ts
│   ├── handlers/
│   │   └── audit-domain-event.handler.ts  ← Subscribe IAuditableEvent
│   └── services/
│       └── audit-log.service.ts            ← Implements IAuditLogService
└── infrastructure/
    ├── persistence/
    │   └── drizzle-audit-log.repository.ts ← Drizzle write
    └── dtos/
        └── audit-entry.dto.ts
```

**Lý do Tier 1:** AuditLog không phụ thuộc module nào, nhưng mọi module đều có thể phụ thuộc vào nó (inject `IAuditLogService`).

---

### 6. Scalability Strategy (Scale sau này)

| Giai đoạn | Giải pháp | Trigger |
|-----------|-----------|---------|
| **MVP** | Write thẳng PostgreSQL synchronous | < 100 req/s |
| **Scale 1** | Queue với BullMQ (Redis), write async | 100–1000 req/s |
| **Scale 2** | Partition bảng theo tháng (PostgreSQL native) | > 1M records |
| **Scale 3** | TimescaleDB hypertable hoặc ClickHouse | > 10M records/tháng |
| **Compliance** | Export S3 (cold storage) + Retention Policy | Luật lưu trữ 5–7 năm |

**Thiết kế hiện tại** tương thích với tất cả giai đoạn nhờ Port/Adapter pattern — chỉ cần thay đổi implementation, không chạm tới domain code.

---

## Proposed Changes

### System Schema

#### [NEW] `src/database/schema/system/audit-logs.schema.ts`
- Bảng `audit_logs` với `bigserial`, indexes, JSONB before/after, partition-ready

---

### Core Layer

#### [NEW] `src/core/shared/domain/events/auditable-event.interface.ts`
- Interface `IAuditableEvent extends IDomainEvent`

#### [NEW] `src/core/shared/application/ports/audit-log.port.ts`
- Port `IAuditLogService` với `log()`, `logBatch()`, `query()`

#### [MODIFY] `src/core/interceptors/` (thêm file)
- `audit.interceptor.ts` — HTTP-level capture, emit event async

---

### AuditLog Module (NEW — Tier 1)

#### [NEW] `src/modules/audit-log/audit-log.module.ts`
#### [NEW] `src/modules/audit-log/domain/audit-log.entity.ts`
#### [NEW] `src/modules/audit-log/application/services/audit-log.service.ts`
#### [NEW] `src/modules/audit-log/application/handlers/audit-domain-event.handler.ts`
#### [NEW] `src/modules/audit-log/infrastructure/persistence/drizzle-audit-log.repository.ts`
#### [NEW] `src/modules/audit-log/infrastructure/dtos/audit-entry.dto.ts`

---

### Schema Index Update

#### [MODIFY] `src/database/schema/index.ts`
- Thêm export `./system/audit-logs.schema`

---

## Open Questions

> [!IMPORTANT]
> **Q1: Scope ban đầu cho MVP?**
> Option A: Chỉ capture HTTP (Interceptor) — nhanh, ít code, không cần sửa domain events.
> Option B: Đầy đủ cả HTTP + Domain Events — hoàn chỉnh hơn nhưng cần retrofit các event hiện có.
> **Khuyến nghị: Bắt đầu Option A, thêm B dần.**

> [!IMPORTANT]
> **Q2: Retention Policy?**
> - Bao lâu thì xóa logs cũ trong PostgreSQL (30, 90, 365 ngày)?
> - Có cần archive ra S3 trước khi xóa không?

> [!WARNING]
> **Q3: Sensitive Data?**
> Một số field như `password`, `token` không được ghi vào `before/after`.
> Cần danh sách blacklist fields để mask trước khi lưu.

---

## Verification Plan

### Automated Tests
- Unit test `AuditLogService.log()` — mock repository
- Unit test `AuditInterceptor` — mock event bus
- Integration test: POST `/leads` → verify `audit_logs` có 1 record mới

### Manual Verification
- Chạy `NODE_ENV=development npx drizzle-kit push` để apply schema
- Gọi 1 API bất kỳ → check bảng `audit_logs` có data
- Query theo `actor_id` và `resource` để xác nhận đúng context
