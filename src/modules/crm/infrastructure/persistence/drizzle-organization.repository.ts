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
export class DrizzleOrganizationRepository
  extends DrizzleBaseRepository
  implements IOrganizationRepository
{
  constructor(@Inject(DRIZZLE) db: NodePgDatabase<typeof schema>) {
    super(db);
  }

  async findById(id: number): Promise<Organization | null> {
    const row = await this.getDb().query.organizations.findFirst({
      where: eq(schema.organizations.id, id),
    });
    return OrganizationMapper.toDomain(row);
  }

  async save(org: Organization): Promise<Organization> {
    const db = this.getDb();
    const data = OrganizationMapper.toPersistence(org);

    let result;
    if (data.id) {
      // Đã có ID -> Chạy lệnh UPDATE toàn bộ các field
      const [updated] = await db
        .update(schema.organizations)
        .set(data)
        .where(eq(schema.organizations.id, data.id))
        .returning();
      result = updated;
    } else {
      // Chưa có ID -> Chạy lệnh INSERT
      const [inserted] = await db
        .insert(schema.organizations)
        .values(data)
        .returning();
      result = inserted;
    }

    return OrganizationMapper.toDomain(result)!;
  }
}

