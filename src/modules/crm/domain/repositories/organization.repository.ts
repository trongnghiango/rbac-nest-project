// src/modules/crm/domain/repositories/organization.repository.ts
import { Organization } from '../entities/organization.entity';

export const IOrganizationRepository = Symbol('IOrganizationRepository');

export interface IOrganizationRepository {
    findById(id: number): Promise<Organization | null>;
    save(org: Organization): Promise<Organization>;
    update(id: number, data: Partial<Organization>): Promise<void>;
}
