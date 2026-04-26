import { Injectable, Logger, Inject } from '@nestjs/common';
import { ACTIVITY_FEED_PORT, IActivityFeedService } from '@core/shared/application/ports/activity-feed.port';
import { AUDIT_LOG_PORT, IAuditLogService, AuditLogSeverity } from '@core/shared/application/ports/audit-log.port';

@Injectable()
export class VerifyActivityFeedScript {
    private readonly logger = new Logger(VerifyActivityFeedScript.name);

    constructor(
        @Inject(ACTIVITY_FEED_PORT) private readonly activityFeedService: IActivityFeedService,
        @Inject(AUDIT_LOG_PORT) private readonly auditLogService: IAuditLogService
    ) {}

    async run(orgId: number) {
        this.logger.log(`🚀 Bắt đầu kiểm chứng Activity Feed cho Org: ${orgId}`);

        // 1. Tạo một hành động giả để test
        await this.auditLogService.log({
            action: 'TEST.ACTIVITY_CHECK',
            resource: 'leads',
            resourceId: '999',
            organizationId: orgId,
            actorId: 'SYSTEM',
            actorName: 'Verify Script',
            severity: AuditLogSeverity.INFO,
            metadata: { info: 'Kiểm tra tính năng timeline' }
        });

        this.logger.debug('Đã ghi log test, đang chờ 1s để DB cập nhật...');
        await new Promise(resolve => setTimeout(resolve, 1000));

        // 2. Lấy timeline
        const result = await this.activityFeedService.getTimeline({
            organizationId: orgId,
            page: 1,
            limit: 20
        });

        console.log(`\n✅ Kết quả: Tìm thấy ${result.items.length} hoạt động.`);
        
        result.items.forEach((item, index) => {
            console.log(`   [${index + 1}] [${item.action}] ${item.action} at ${item.createdAt}`);
        });

        if (result.items.length > 0) {
            this.logger.log('✅ Activity Feed hoạt động tốt!');
            return true;
        }

        this.logger.error('❌ Không tìm thấy hoạt động nào trong timeline.');
        return false;
    }
}
