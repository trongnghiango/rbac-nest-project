import { pgTable, bigserial, integer, varchar, text, jsonb, timestamp, index } from 'drizzle-orm/pg-core';

/**
 * AUDIT_LOGS — Nhật ký hành động toàn hệ thống
 *
 * Thiết kế nguyên tắc:
 * 1. KHÔNG có FK về users/employees — audit record tồn tại độc lập kể cả khi actor bị xóa.
 * 2. bigserial thay vì serial — chuẩn bị cho hàng triệu records.
 * 3. before/after là JSONB diff — tối ưu storage so với lưu full object.
 * 4. Partition-ready theo created_at — có thể bật pg_partman sau khi > 1M records.
 */
export const auditLogs = pgTable(
    'audit_logs',
    {
        id: bigserial('id', { mode: 'number' }).primaryKey(),

        // ── WHO ──────────────────────────────────────────────
        actor_id:   integer('actor_id'),                          // null = system/migration/cron
        actor_type: varchar('actor_type', { length: 20 }).default('USER'),  // USER | SYSTEM | API_KEY
        actor_name: varchar('actor_name', { length: 100 }),       // snapshot tên tại thời điểm action
        actor_ip:   varchar('actor_ip', { length: 45 }),          // IPv4 or IPv6

        // ── WHAT ─────────────────────────────────────────────
        action:      varchar('action', { length: 100 }).notNull(), // e.g. 'LEAD.STAGE_CHANGED'
        resource:    varchar('resource', { length: 50 }).notNull(),// e.g. 'leads'
        resource_id: varchar('resource_id', { length: 50 }),      // e.g. '123'

        // ── CHANGE SNAPSHOT ───────────────────────────────────
        before: jsonb('before'),  // state trước khi thay đổi (null = CREATE action)
        after:  jsonb('after'),   // state sau khi thay đổi (null = DELETE action)

        // ── REQUEST CONTEXT ───────────────────────────────────
        request_id: varchar('request_id', { length: 64 }),
        user_agent: text('user_agent'),
        metadata:   jsonb('metadata'), // extra context tùy action (e.g. reason, note)

        // ── SEVERITY ─────────────────────────────────────────
        severity: varchar('severity', { length: 10 }).default('INFO').notNull(), // INFO | WARN | CRITICAL

        // ── WHEN ─────────────────────────────────────────────
        created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    },
    (t) => ({
        actor_idx:    index('idx_audit_actor').on(t.actor_id),
        resource_idx: index('idx_audit_resource').on(t.resource, t.resource_id),
        created_idx:  index('idx_audit_created').on(t.created_at),
        action_idx:   index('idx_audit_action').on(t.action),
        severity_idx: index('idx_audit_severity').on(t.severity),
    }),
);

export type AuditLogInsert = typeof auditLogs.$inferInsert;
export type AuditLogSelect = typeof auditLogs.$inferSelect;
