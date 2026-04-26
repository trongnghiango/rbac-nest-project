import { Injectable, Inject } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE } from '@database/drizzle.provider';
import * as schema from '@database/schema';
import { IAuditLogService, AuditLogEntry } from '@core/shared/application/ports/audit-log.port';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { and, eq } from 'drizzle-orm';

@Injectable()
export class DrizzleAuditLogService extends DrizzleBaseRepository implements IAuditLogService {
    constructor(
        @Inject(DRIZZLE) db: NodePgDatabase<typeof schema>,
    ) {
        super(db);
    }

    async log(entry: AuditLogEntry): Promise<void> {
        const db = this.getDb();
        
        await db.insert(schema.auditLogs).values({
            action: entry.action,
            resource: entry.resource,
            resourceId: entry.resourceId,
            organizationId: entry.organizationId,
            actorId: entry.actorId ? Number(entry.actorId) : null,
            actorName: entry.actorName,
            before: entry.before,
            after: entry.after,
            metadata: entry.metadata,
            severity: (entry.severity as any) || 'INFO',
            actorIp: entry.ipAddress,
            userAgent: entry.userAgent,
            requestId: entry.requestId
        });
    }

    async query(filter: { action?: string; resource?: string; resourceId?: string }): Promise<any[]> {
        const db = this.getDb();
        const conditions = [];
        
        if (filter.action) conditions.push(eq(schema.auditLogs.action, filter.action));
        if (filter.resource) conditions.push(eq(schema.auditLogs.resource, filter.resource));
        if (filter.resourceId) conditions.push(eq(schema.auditLogs.resourceId, filter.resourceId));

        return await db.query.auditLogs.findMany({
            where: conditions.length > 0 ? and(...conditions) : undefined,
            orderBy: (t, { desc }) => [desc(t.createdAt)],
            limit: 100
        });
    }
}
