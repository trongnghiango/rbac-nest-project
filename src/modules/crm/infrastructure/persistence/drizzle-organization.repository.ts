// src/modules/crm/infrastructure/persistence/drizzle-organization.repository.ts
import { Injectable, Inject } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { Organization } from '../../domain/entities/organization.entity';
import { OrganizationMapper } from '../mappers/organization.mapper';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { IOrganizationRepository } from '@modules/crm/domain/repositories/organization.repository';


@Injectable()
export class DrizzleOrganizationRepository extends DrizzleBaseRepository implements IOrganizationRepository {
    constructor(@Inject(DRIZZLE) db: NodePgDatabase<typeof schema>) {
        super(db);
    }

    async findById(id: number): Promise<Organization | null> {
        const row = await this.getDb().query.organizations.findFirst({ where: eq(schema.organizations.id, id) });
        return OrganizationMapper.toDomain(row);
    }

    async save(org: Organization): Promise<Organization> {
        const data = OrganizationMapper.toPersistence(org);
        const [result] = await this.getDb().insert(schema.organizations).values(data as any).onConflictDoUpdate({
            target: schema.organizations.id,
            set: data,
        }).returning();
        return OrganizationMapper.toDomain(result);
    }

    async update(id: number, data: Partial<Organization>): Promise<void> {
        // SỬA TẠI ĐÂY: Không dùng new Organization(...) bằng positional args
        // Mà dùng object mapping chuẩn
        const persistenceData = {
            company_name: data.companyName,
            tax_code: data.taxCode,
            type: data.type,
            status: data.status,
            is_internal: data.isInternal,
            industry: data.industry,
            website: data.website,
            address: data.address,
            note: data.note,
            updated_at: new Date()
        };

        // Loại bỏ các trường undefined
        Object.keys(persistenceData).forEach(key =>
            (persistenceData as any)[key] === undefined && delete (persistenceData as any)[key]
        );

        await this.getDb().update(schema.organizations)
            .set(persistenceData as any)
            .where(eq(schema.organizations.id, id));
    }
}