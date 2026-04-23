// src/modules/accounting/domain/events/finote-created.event.ts
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

export class FinoteCreatedEvent implements IDomainEvent {
    static readonly EVENT_NAME = 'FinoteCreated';
    readonly occurredAt = new Date();

    constructor(
        public readonly aggregateId: string, // ID của Finote
        public readonly payload: {
            finoteId: number;
            code: string;
            type: string;
            title: string;
            amount: string;
            creatorId: number;
            orgId?: number | null;
        },
    ) { }
}
