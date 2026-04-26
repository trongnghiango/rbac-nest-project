// src/modules/crm/infrastructure/mappers/contact.mapper.ts
import { Contact } from '../../domain/entities/contact.entity';

export class ContactMapper {
    static toDomain(raw: any): Contact | null {
        if (!raw) return null;

        return new Contact({
            id: raw.id,
            organizationId: raw.organizationId,
            fullName: raw.fullName,
            phone: raw.phone,
            email: raw.email,
            position: raw.jobTitle,
            isMain: raw.isPrimary,
            createdAt: raw.createdAt,
            updatedAt: raw.updatedAt,
        });
    }

    static toPersistence(domain: Contact): any {
        return {
            id: domain.id,
            organizationId: domain.organizationId,
            fullName: domain.fullName,
            phone: domain.phone,
            email: domain.email,
            jobTitle: domain.position,
            isPrimary: domain.isMain,
            updatedAt: new Date(),
        };
    }
}
