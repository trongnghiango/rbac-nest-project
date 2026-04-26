import { Injectable, Inject, Logger } from '@nestjs/common';
import { IAuditLogService, AUDIT_LOG_PORT } from '@core/shared/application/ports/audit-log.port';
import { IAuditableEvent } from '@core/shared/domain/events/auditable-event.interface';
import { EventHandler } from '@core/shared/infrastructure/event-bus/decorators/event-handler.decorator';
import { ClientOnboardedEvent } from '@modules/crm/onboarding/domain/events/client-onboarded.event';

@Injectable()
export class AuditDomainEventHandler {
    private readonly logger = new Logger(AuditDomainEventHandler.name);

    constructor(
        @Inject(AUDIT_LOG_PORT) private readonly auditLogService: IAuditLogService
    ) {}

    /**
     * Tự động ghi Audit Log khi nhận được sự kiện ClientOnboarded (vì nó implement IAuditableEvent)
     */
    @EventHandler(ClientOnboardedEvent)
    async onClientOnboarded(event: ClientOnboardedEvent) {
        this.logger.debug(`[AuditHandler] Processing auditable event: ${event.constructor.name}`);
        this.handleAuditable(event);
    }

    /**
     * Logic chung để xử lý mọi Auditable Event
     */
    private handleAuditable(event: IAuditableEvent) {
        try {
            const entry = event.toAuditEntry();
            this.auditLogService.log({
                ...entry,
                metadata: {
                    ...entry.metadata,
                    triggeredByEvent: event.constructor.name,
                    occurredAt: event.occurredAt
                }
            });
        } catch (error) {
            this.logger.error(`Failed to process audit event: ${event.constructor.name}`, error);
        }
    }
}
