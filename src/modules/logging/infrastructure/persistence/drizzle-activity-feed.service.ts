import { Injectable, Inject } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE } from '@database/drizzle.provider';
import * as schema from '@database/schema';
import { 
    IActivityFeedService, 
    ActivityFeedQuery, 
    ActivityItem 
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

    async getTimeline(query: ActivityFeedQuery): Promise<{ items: ActivityItem[]; total: number; }> {
        const db = this.getDb();
        const page = query.page || 1;
        const limit = query.limit || 20;
        const offset = (page - 1) * limit;

        // 1. Query Audit Logs
        const auditItemsRaw = await db.query.auditLogs.findMany({
            where: eq(schema.auditLogs.organization_id, query.organizationId),
            orderBy: [desc(schema.auditLogs.created_at)],
            limit: limit * 2, // Lấy nhiều hơn một chút để merge
        });

        const auditItems: ActivityItem[] = auditItemsRaw.map(item => ({
            id: `audit-${item.id}`,
            timestamp: item.created_at,
            type: 'SYSTEM_AUDIT',
            actor: {
                id: item.actor_id,
                name: item.actor_name || 'Hệ thống',
            },
            action: item.action,
            displayText: this.formatAuditAction(item),
            severity: item.severity as any,
            metadata: item.metadata,
            reference: {
                type: item.resource,
                id: item.resource_id,
            }
        }));

        // 2. Query Interaction Notes
        const noteItemsRaw = await db.query.interactionNotes.findMany({
            where: eq(schema.interactionNotes.organization_id, query.organizationId),
            orderBy: [desc(schema.interactionNotes.created_at)],
            limit: limit * 2,
            with: {
                creator: true
            }
        });

        const noteItems: ActivityItem[] = noteItemsRaw.map(item => ({
            id: `note-${item.id}`,
            timestamp: item.created_at,
            type: 'HUMAN_NOTE',
            actor: {
                id: item.created_by_id,
                name: (item.creator as any)?.username || 'Ẩn danh',
            },
            action: `NOTE.${item.type}`,
            displayText: item.content,
            severity: 'INFO',
            metadata: item.metadata,
        }));

        // 3. Merge and Sort
        let allItems = [...auditItems, ...noteItems];
        allItems.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

        return {
            items: allItems.slice(offset, offset + limit),
            total: allItems.length // Tạm thời trả về tổng số item đã load được
        };
    }

    private formatAuditAction(item: any): string {
        switch (item.action) {
            case 'LEAD.CLOSE_WON':
                return `Đã chốt hợp đồng thành công từ Lead.`;
            case 'PAYMENT.ALLOCATED':
                return `Đã ghi nhận thanh toán cho giao dịch.`;
            case 'USER.PROVISIONED':
                return `Đã khởi tạo tài khoản người dùng mới.`;
            case 'RBAC.ROLE_ASSIGNED':
                return `Đã gán quyền mới cho thành viên.`;
            default:
                return `${item.action} trên ${item.resource}`;
        }
    }
}
