import { Injectable } from '@nestjs/common';
import { eq, desc } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { clinics } from '@database/schema';

import { IClinicRepository } from '../../../domain/repositories/clinic.repository';
import {
  CreateClinicDto,
  UpdateClinicDto,
} from '../../../application/dtos/clinic.dto';

@Injectable()
export class DrizzleClinicRepository
  extends DrizzleBaseRepository
  implements IClinicRepository
{
  async findClinicByCode(
    code: string,
    tx?: Transaction,
  ): Promise<{ id: number } | null> {
    const db = this.getDb(tx);
    const res = await db
      .select({ id: clinics.id })
      .from(clinics)
      .where(eq(clinics.clinicCode, code))
      .limit(1);
    return res[0] || null;
  }

  async createClinic(
    data: CreateClinicDto,
    tx?: Transaction,
  ): Promise<{ id: number }> {
    const db = this.getDb(tx);
    const [res] = await db
      .insert(clinics)
      .values({
        name: data.name,
        clinicCode: data.clinicCode,
        address: data.address,
        phoneNumber: data.phoneNumber,
      })
      .returning({ id: clinics.id });
    return res;
  }

  // --- CRUD ---

  async findAll(): Promise<any[]> {
    return this.db.select().from(clinics).orderBy(desc(clinics.createdAt));
  }

  async findById(id: number): Promise<any | null> {
    const res = await this.db.select().from(clinics).where(eq(clinics.id, id));
    return res[0] || null;
  }

  async update(
    id: number,
    data: UpdateClinicDto,
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);
    await db
      .update(clinics)
      .set({
        ...data,
        updatedAt: new Date(),
      })
      .where(eq(clinics.id, id));
  }
}
