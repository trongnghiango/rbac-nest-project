export class ServiceAssignment {
    constructor(
        public readonly id: number,
        public readonly organizationId: number,
        public readonly employeeId: number,
        public readonly role: string,
        public readonly assignedAt: Date,
    ) { }

}
