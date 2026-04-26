import { pgTable, bigserial, integer, varchar, text, jsonb, timestamp, index, bigint } from 'drizzle-orm/pg-core';

export const auditLogs = pgTable(
    'audit_logs',
    {
        id: bigserial('id', { mode: 'number' }).primaryKey(),

        // ── WHO ──────────────────────────────────────────────
        actorId:   integer('actor_id'),                          // null = system/migration/cron
        actorType: varchar('actor_type', { length: 20 }).default('USER'),  // USER | SYSTEM | API_KEY
        actorName: varchar('actor_name', { length: 100 }),       // snapshot tên tại thời điểm action
        actorIp:   varchar('actor_ip', { length: 45 }),          // IPv4 or IPv6

        // ── WHAT ─────────────────────────────────────────────
        action:      varchar('action', { length: 100 }).notNull(), // e.g. 'LEAD.STAGE_CHANGED'
        resource:    varchar('resource', { length: 50 }).notNull(),// e.g. 'leads'
        resourceId: varchar('resource_id', { length: 50 }),      // e.g. '123'
        organizationId: bigint('organization_id', { mode: 'number' }),

        // ── CHANGE SNAPSHOT ───────────────────────────────────
        before: jsonb('before'),  // state trước khi thay đổi (null = CREATE action)
        after:  jsonb('after'),   // state sau khi thay đổi (null = DELETE action)

        // ── REQUEST CONTEXT ───────────────────────────────────
        requestId: varchar('request_id', { length: 64 }),
        userAgent: text('user_agent'),
        metadata:   jsonb('metadata'), // extra context tùy action (e.g. reason, note)

        // ── SEVERITY ─────────────────────────────────────────
        severity: varchar('severity', { length: 10 }).default('INFO').notNull(), // INFO | WARN | CRITICAL

        // ── WHEN ─────────────────────────────────────────────
        createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    },
    (t) => ({
        actor_idx:    index('idx_audit_actor').on(t.actorId),
        resource_idx: index('idx_audit_resource').on(t.resource, t.resourceId),
        created_idx:  index('idx_audit_created').on(t.createdAt),
        action_idx:   index('idx_audit_action').on(t.action),
        severity_idx: index('idx_audit_severity').on(t.severity),
    }),
);

export type AuditLogInsert = typeof auditLogs.$inferInsert;
export type AuditLogSelect = typeof auditLogs.$inferSelect;
