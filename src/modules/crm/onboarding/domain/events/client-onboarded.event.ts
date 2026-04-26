import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

export class ClientOnboardedEvent implements IDomainEvent {
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
}
