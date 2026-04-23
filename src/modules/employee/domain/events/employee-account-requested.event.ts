import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

export class EmployeeAccountRequestedEvent implements IDomainEvent {
    static readonly EVENT_NAME = 'EmployeeAccountRequested';
    readonly occurredAt = new Date();

    constructor(
        public readonly aggregateId: string, // employeeId
        public readonly payload: {
            employeeId: number;
            email: string;
            username: string;
            fullName: string;
            organizationId: number; // <--- BỔ SUNG DÒNG NÀY
        },
    ) { }
}
