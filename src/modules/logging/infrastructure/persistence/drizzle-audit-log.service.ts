import { Injectable, Inject } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE } from '@database/drizzle.provider';
import * as schema from '@database/schema';
import { IAuditLogService, AuditLogEntry } from '@core/shared/application/ports/audit-log.port';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { and, eq } from 'drizzle-orm';

import { RequestContextService } from '@core/shared/infrastructure/context/request-context.service';

@Injectable()
export class DrizzleAuditLogService extends DrizzleBaseRepository implements IAuditLogService {
    constructor(
        @Inject(DRIZZLE) db: NodePgDatabase<typeof schema>,
    ) {
        super(db);
    }

    log(entry: AuditLogEntry): void {
        // Capture context immediately
        const context = RequestContextService.getContext();
        const requestId = entry.requestId || context?.requestId || 'sys-' + process.pid;
        const actorId = entry.actorId || context?.userId;
        const actorName = entry.actorName || context?.userName;
        const ipAddress = entry.ipAddress || context?.ip;
        const userAgent = entry.userAgent || context?.userAgent;
        
        // Sử dụng this.db thay vì getDb() để đảm bảo thoát khỏi transaction context hiện tại
        setImmediate(async () => {
            try {
                await this.db.insert(schema.auditLogs).values({
                    action: entry.action,
                    resource: entry.resource,
                    resourceId: entry.resourceId,
                    organizationId: entry.organizationId,
                    actorId: actorId ? Number(actorId) : null,
                    actorName: actorName,
                    before: entry.before,
                    after: entry.after,
                    metadata: entry.metadata,
                    severity: (entry.severity as any) || 'INFO',
                    actorIp: ipAddress,
                    userAgent: userAgent,
                    requestId: requestId
                });
            } catch (error) {
                console.error('[AuditLog Async Error]: Ghi log thất bại', error);
            }
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
