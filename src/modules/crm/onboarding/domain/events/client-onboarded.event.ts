import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';
import { IAuditableEvent, AuditEntryPayload } from '@core/shared/domain/events/auditable-event.interface';

export class ClientOnboardedEvent implements IDomainEvent, IAuditableEvent {
    static readonly EVENT_NAME = 'CLIENT_ONBOARDED';
    
    constructor(
        public readonly aggregateId: string,
        public readonly occurredAt: Date,
        public readonly payload: {
            orgId: number;
            contractId: number;
            contractNumber: string;
        }
    ) {}

    toAuditEntry(): AuditEntryPayload {
        return {
            action: 'LEAD.CLOSE_WON',
            resource: 'leads',
            resourceId: this.aggregateId,
            organizationId: this.payload.orgId,
            after: { 
                contractId: this.payload.contractId,
                contractNumber: this.payload.contractNumber
            },
            severity: 'INFO'
        };
    }
}
