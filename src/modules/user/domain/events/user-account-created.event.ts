import { IDomainEvent } from "@core/shared/domain/events/domain-event.interface";

//
export class UserAccountCreatedEvent implements IDomainEvent {
    static readonly EVENT_NAME = 'UserAccountCreated';
    readonly occurredAt = new Date();
    constructor(
        public readonly aggregateId: string, // userId
        public readonly payload: {
            userId: number;
            username: string;
            metadata: Record<string, any>; // Chứa thông tin bổ sung như employeeId
        },
    ) { }
}