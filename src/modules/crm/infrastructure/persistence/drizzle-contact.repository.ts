// src/modules/crm/infrastructure/persistence/drizzle-contact.repository.ts
import { Injectable, Inject } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { Contact } from '../../domain/entities/contact.entity';
import { ContactMapper } from '../mappers/contact.mapper';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { IContactRepository } from '@modules/crm/domain/repositories/contact.repository';

@Injectable()
export class DrizzleContactRepository
  extends DrizzleBaseRepository
  implements IContactRepository
{
  constructor(@Inject(DRIZZLE) db: NodePgDatabase<typeof schema>) {
    super(db);
  }

  async findById(id: number): Promise<Contact | null> {
    const row = await this.getDb().query.contacts.findFirst({
      where: eq(schema.contacts.id, id),
    });
    return ContactMapper.toDomain(row);
  }

  async findByPhone(phone: string): Promise<Contact | null> {
    const row = await this.getDb().query.contacts.findFirst({
      where: eq(schema.contacts.phone, phone),
    });
    return ContactMapper.toDomain(row);
  }

  async save(contact: Contact): Promise<Contact> {
    const db = this.getDb();
    const data = ContactMapper.toPersistence(contact);

    let result;
    if (data.id) {
       const [updated] = await db
        .update(schema.contacts)
        .set(data)
        .where(eq(schema.contacts.id, data.id))
        .returning();
      result = updated;
    } else {
      const [inserted] = await db
        .insert(schema.contacts)
        .values(data)
        .returning();
      result = inserted;
    }

    return ContactMapper.toDomain(result)!;
  }
}
