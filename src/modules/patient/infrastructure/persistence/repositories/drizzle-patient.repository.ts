import { Injectable } from '@nestjs/common';
import { eq, desc } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { patients } from '@database/schema';

import { IPatientRepository } from '../../../domain/repositories/patient.repository';
import {
  CreatePatientDto,
  UpdatePatientDto,
} from '../../../application/dtos/patient.dto';

@Injectable()
export class DrizzlePatientRepository
  extends DrizzleBaseRepository
  implements IPatientRepository
{
  async findPatientByCode(
    code: string,
    tx?: Transaction,
  ): Promise<{ id: number } | null> {
    const db = this.getDb(tx);
    const res = await db
      .select({ id: patients.id })
      .from(patients)
      .where(eq(patients.patientCode, code))
      .limit(1);
    return res[0] || null;
  }

  async createPatient(
    data: CreatePatientDto,
    tx?: Transaction,
  ): Promise<{ id: number }> {
    const db = this.getDb(tx);
    const [res] = await db
      .insert(patients)
      .values({
        fullName: data.fullName,
        patientCode: data.patientCode,
        clinicId: data.clinicId,
        gender: data.gender,
        birthDate: data.birthDate,
        phoneNumber: data.phoneNumber,
        email: data.email,
        address: data.address,
      })
      .returning({ id: patients.id });
    return res;
  }

  // --- CRUD ---

  async findAll(clinicId?: number): Promise<any[]> {
    const query = this.db.select().from(patients);
    if (clinicId) {
      query.where(eq(patients.clinicId, clinicId));
    }
    return query.orderBy(desc(patients.createdAt));
  }

  async findById(id: number): Promise<any | null> {
    const res = await this.db
      .select()
      .from(patients)
      .where(eq(patients.id, id));
    return res[0] || null;
  }

  async update(
    id: number,
    data: UpdatePatientDto,
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);
    await db
      .update(patients)
      .set({
        ...data,
        updatedAt: new Date(),
      })
      .where(eq(patients.id, id));
  }
}
