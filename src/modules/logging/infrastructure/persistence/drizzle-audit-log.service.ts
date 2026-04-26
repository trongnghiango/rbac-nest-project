import { Injectable, Inject } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE } from '@database/drizzle.provider';
import * as schema from '@database/schema';
import { 
    IAuditLogService, 
    AuditEntryDto, 
    AuditQueryDto, 
    PaginatedAuditResult 
} from '@core/shared/application/ports/audit-log.port';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { desc, eq, and, gte, lte } from 'drizzle-orm';

@Injectable()
export class DrizzleAuditLogService extends DrizzleBaseRepository implements IAuditLogService {
    constructor(
        @Inject(DRIZZLE) db: NodePgDatabase<typeof schema>,
    ) {
        super(db);
    }

    async log(entry: AuditEntryDto): Promise<void> {
        try {
            const db = this.getDb();
            await db.insert(schema.auditLogs).values({
                actor_id: entry.actor_id,
                actor_type: (entry.actor_type as any) || 'USER',
                actor_name: entry.actor_name,
                actor_ip: entry.actor_ip,
                action: entry.action,
                resource: entry.resource,
                resource_id: entry.resource_id,
                before: entry.before,
                after: entry.after,
                request_id: entry.request_id,
                user_agent: entry.user_agent,
                metadata: entry.metadata,
                severity: entry.severity || 'INFO',
                organization_id: entry.organization_id,
            });
        } catch (error) {
            // Fire-and-forget: Fail silently for audit logs to not block business logic
            console.error('Failed to write audit log:', error);
        }
    }

    async logBatch(entries: AuditEntryDto[]): Promise<void> {
        try {
            const db = this.getDb();
            const values = entries.map(entry => ({
                actor_id: entry.actor_id,
                actor_type: (entry.actor_type as any) || 'USER',
                actor_name: entry.actor_name,
                actor_ip: entry.actor_ip,
                action: entry.action,
                resource: entry.resource,
                resource_id: entry.resource_id,
                before: entry.before,
                after: entry.after,
                request_id: entry.request_id,
                user_agent: entry.user_agent,
                metadata: entry.metadata,
                severity: entry.severity || 'INFO',
                organization_id: entry.organization_id,
            }));
            await db.insert(schema.auditLogs).values(values);
        } catch (error) {
            console.error('Failed to write batch audit logs:', error);
        }
    }

    async query(filter: AuditQueryDto): Promise<PaginatedAuditResult> {
        const db = this.getDb();
        const page = filter.page || 1;
        const limit = filter.limit || 20;
        const offset = (page - 1) * limit;

        const whereClauses = [];
        if (filter.actor_id) whereClauses.push(eq(schema.auditLogs.actor_id, filter.actor_id));
        if (filter.resource) whereClauses.push(eq(schema.auditLogs.resource, filter.resource));
        if (filter.resource_id) whereClauses.push(eq(schema.auditLogs.resource_id, filter.resource_id));
        if (filter.action) whereClauses.push(eq(schema.auditLogs.action, filter.action));
        if (filter.severity) whereClauses.push(eq(schema.auditLogs.severity, filter.severity));
        if (filter.from) whereClauses.push(gte(schema.auditLogs.created_at, filter.from));
        if (filter.to) whereClauses.push(lte(schema.auditLogs.created_at, filter.to));

        const where = whereClauses.length > 0 ? and(...whereClauses) : undefined;

        const data = await db.query.auditLogs.findMany({
            where,
            limit,
            offset,
            orderBy: [desc(schema.auditLogs.created_at)],
        });

        // For total count, we might need a separate query or a more complex one.
        // Simplified for now as Drizzle doesn't return count in findMany easily without extra query.
        const totalResult = await db.execute(require('drizzle-orm').sql`SELECT count(*) FROM audit_logs`);
        const total = Number((totalResult.rows[0] as any).count);

        return {
            data: data as any,
            total,
            page,
            limit
        };
    }
}
