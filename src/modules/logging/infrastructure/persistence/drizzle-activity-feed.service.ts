import { Injectable, Inject } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE } from '@database/drizzle.provider';
import * as schema from '@database/schema';
import { 
    IActivityFeedService, 
    ActivityFeedItem, 
    GetTimelineQuery, 
    ActivityFeedResponse 
} from '@core/shared/application/ports/activity-feed.port';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { desc, eq } from 'drizzle-orm';

@Injectable()
export class DrizzleActivityFeedService extends DrizzleBaseRepository implements IActivityFeedService {
    constructor(
        @Inject(DRIZZLE) db: NodePgDatabase<typeof schema>,
    ) {
        super(db);
    }

    async getTimeline(query: GetTimelineQuery): Promise<ActivityFeedResponse> {
        const db = this.getDb();
        const limit = query.limit || 50;
        const offset = ((query.page || 1) - 1) * limit;
        
        const logs = await db.query.auditLogs.findMany({
            where: eq(schema.auditLogs.organizationId, query.organizationId),
            orderBy: [desc(schema.auditLogs.createdAt)],
            limit: limit,
            offset: offset,
        });

        const items = logs.map(log => ({
            id: log.id,
            action: log.action,
            resource: log.resource,
            resourceId: log.resourceId,
            organizationId: log.organizationId,
            actorId: log.actorId || 'SYSTEM',
            actorName: log.actorName || 'System',
            severity: log.severity,
            createdAt: log.createdAt,
            metadata: log.metadata as any
        })) as ActivityFeedItem[];

        return { items };
    }
}
