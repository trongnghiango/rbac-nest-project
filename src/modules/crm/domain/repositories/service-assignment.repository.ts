// src/modules/crm/domain/repositories/service-assignment.repository.ts
export const IServiceAssignmentRepository = Symbol('IServiceAssignmentRepository');

export interface IServiceAssignmentRepository {
    replaceByOrganization(orgId: number, assignments: any[]): Promise<void>;
}
