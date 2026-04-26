import { Injectable, OnModuleInit, Inject, Logger } from '@nestjs/common';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { AUDIT_LOG_PORT, IAuditLogService } from '@core/shared/application/ports/audit-log.port';

@Injectable()
export class ClientOnboardedHandler implements OnModuleInit {
    private readonly logger = new Logger(ClientOnboardedHandler.name);

    constructor(
        @Inject(IEventBus) private readonly eventBus: IEventBus,
        @Inject(AUDIT_LOG_PORT) private readonly auditLog: IAuditLogService,
    ) {}

    onModuleInit() {
        this.eventBus.subscribe('CLIENT_ONBOARDED', async (event: any) => {
            await this.handle(event);
        });
    }

    private async handle(event: any) {
        const { orgId, contractId, contractNumber } = event.payload;
        this.logger.log(`[ONBOARDING] Bắt đầu kích hoạt cho Org: ${orgId} (Hợp đồng: ${contractNumber})`);

        // Giả lập các bước Automation
        try {
            // Bước 1: Khởi tạo Billing (Ghi log để vết)
            this.auditLog.log({
                action: 'ONBOARDING.BILLING_INIT',
                resource: 'organizations',
                resourceId: orgId.toString(),
                organizationId: orgId,
                actorName: 'ONBOARDING_ENGINE',
                metadata: { contractId, step: 'AUTO_BILLING' }
            });

            // Bước 2: Thông báo đội ngũ
            this.logger.debug(`-> Đã gửi thông báo cho đội ngũ triển khai dự án.`);

            // Bước 3: Hoàn tất
            this.auditLog.log({
                action: 'ONBOARDING.COMPLETED',
                resource: 'organizations',
                resourceId: orgId.toString(),
                organizationId: orgId,
                actorName: 'ONBOARDING_ENGINE',
                metadata: { status: 'SUCCESS' }
            });

            this.logger.log(`✅ Onboarding thành công cho Org ${orgId}`);

        } catch (error) {
            this.logger.error(`❌ Lỗi Onboarding cho Org ${orgId}:`, error);
        }
    }
}
