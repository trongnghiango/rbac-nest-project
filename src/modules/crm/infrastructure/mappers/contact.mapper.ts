// src/modules/crm/infrastructure/mappers/contact.mapper.ts
import { Contact } from '../../domain/entities/contact.entity';

export class ContactMapper {
    static toDomain(raw: any): Contact | null {
        if (!raw) return null;

        return new Contact({
            id: raw.id,
            organizationId: raw.organization_id,
            fullName: raw.full_name,
            phone: raw.phone,
            email: raw.email,
            position: raw.job_title,
            isMain: raw.is_primary,
            createdAt: raw.created_at,
            updatedAt: raw.updated_at,
        });
    }

    static toPersistence(domain: Contact): any {
        return {
            id: domain.id,
            organization_id: domain.organizationId,
            full_name: domain.fullName,
            phone: domain.phone,
            email: domain.email,
            job_title: domain.position,
            is_primary: domain.isMain,
            updated_at: new Date(),
        };
    }
}
