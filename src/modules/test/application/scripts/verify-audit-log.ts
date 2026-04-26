import { Injectable, Logger, Inject } from '@nestjs/common';
import { AUDIT_LOG_PORT, IAuditLogService, AuditLogSeverity } from '@core/shared/application/ports/audit-log.port';

@Injectable()
export class VerifyAuditLogScript {
    private readonly logger = new Logger(VerifyAuditLogScript.name);

    constructor(
        @Inject(AUDIT_LOG_PORT) private readonly auditService: IAuditLogService
    ) {}

    async run() {
        const testAction = `TEST_ACTION_${Date.now()}`;
        this.logger.log(`🚀 Bắt đầu kiểm chứng Audit Log với Action: ${testAction}`);

        // 1. Ghi log
        await this.auditService.log({
            action: testAction,
            resource: 'test_resource',
            resourceId: '999',
            actorId: 'SYSTEM_TEST',
            actorName: 'Test Script',
            severity: AuditLogSeverity.INFO,
            metadata: { note: 'Đây là log kiểm chứng hệ thống' }
        });

        // 2. Truy vấn lại (sử dụng method query mới thêm)
        if (this.auditService.query) {
            const results = await this.auditService.query({ action: testAction });
            
            if (results.length > 0 && results[0].action === testAction) {
                this.logger.log('✅ Thành công: Đã tìm thấy Audit Log vừa ghi.');
                console.log('Chi tiết log:', JSON.stringify(results[0], null, 2));
                return true;
            }
        }

        this.logger.error('❌ Thất bại: Không tìm thấy Audit Log.');
        return false;
    }
}
