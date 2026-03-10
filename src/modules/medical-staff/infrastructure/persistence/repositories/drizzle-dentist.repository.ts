import { Injectable } from '@nestjs/common';
import { eq, desc, and } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { dentists, clinics } from '@database/schema';

import { IDentistRepository } from '../../../domain/repositories/dentist.repository';
import {
  CreateDentistDto,
  UpdateDentistDto,
} from '../../../application/dtos/dentist.dto';

@Injectable()
export class DrizzleDentistRepository
  extends DrizzleBaseRepository
  implements IDentistRepository
{
  async findDentist(
    name: string,
    clinicId: number,
    tx?: Transaction,
  ): Promise<{ id: number } | null> {
    const db = this.getDb(tx);
    const res = await db
      .select({ id: dentists.id })
      .from(dentists)
      .where(and(eq(dentists.fullName, name), eq(dentists.clinicId, clinicId)))
      .limit(1);
    return res[0] || null;
  }

  async createDentist(
    data: CreateDentistDto,
    tx?: Transaction,
  ): Promise<{ id: number }> {
    const db = this.getDb(tx);
    const [res] = await db
      .insert(dentists)
      .values({
        fullName: data.fullName,
        clinicId: data.clinicId,
        phoneNumber: data.phoneNumber,
        email: data.email,
        userId: data.userId,
      })
      .returning({ id: dentists.id });
    return res;
  }

  // --- CRUD ---

  async findAll(clinicId?: number): Promise<any[]> {
    const query = this.db.select().from(dentists);
    if (clinicId) {
      query.where(eq(dentists.clinicId, clinicId));
    }
    return query.orderBy(desc(dentists.createdAt));
  }

  async findById(id: number): Promise<any | null> {
    const res = await this.db
      .select()
      .from(dentists)
      .where(eq(dentists.id, id));
    return res[0] || null;
  }

  async update(
    id: number,
    data: UpdateDentistDto,
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);
    await db.update(dentists).set(data).where(eq(dentists.id, id));
  }
}
