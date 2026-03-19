import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

export class OtpRequestedEvent implements IDomainEvent {
    static readonly EVENT_NAME = 'OtpRequested';
    readonly occurredAt = new Date();

    constructor(
        public readonly aggregateId: string, // Email của user
        public readonly payload: {
            email: string;
            fullName: string;
            otpCode: string;
        },
    ) { }
}
