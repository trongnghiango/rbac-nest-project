import { Organization, OrganizationStatus, OrganizationType } from '../../domain/entities/organization.entity';

export class OrganizationMapper {
    static toDomain(raw: any): Organization | null {
        if (!raw) return null;
        // Quan trọng: Phải map từ snake_case của DB sang camelCase của Entity
        return new Organization({
            id: raw.id,
            companyName: raw.company_name, // Map ở đây
            taxCode: raw.tax_code,         // Map ở đây
            type: raw.type as OrganizationType,
            status: raw.status as OrganizationStatus,
            isInternal: raw.is_internal,
            industry: raw.industry,
            website: raw.website,
            address: raw.address,
            note: raw.note,
        });
    }

    static toPersistence(domain: Organization) {
        return {
            id: domain.id,
            company_name: domain.companyName,
            tax_code: domain.taxCode,
            type: domain.type,
            status: domain.status,
            is_internal: domain.isInternal,
            industry: domain.industry,
            website: domain.website,
            address: domain.address,
            note: domain.note,
        };
    }
}