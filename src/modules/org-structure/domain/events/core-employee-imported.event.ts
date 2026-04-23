// src/modules/org-structure/domain/events/core-employee-imported.event.ts

import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

export class CoreEmployeeImportedEvent implements IDomainEvent {
    static readonly EVENT_NAME = 'CoreEmployeeImported';
    readonly occurredAt = new Date();
    constructor(
        public readonly aggregateId: string,
        public readonly payload: {
            userId: number;
            employeeCode: string;
            fullName: string;
            organizationId: number;
            positionId: number;
            locationId?: number;
        },
    ) { }
}
