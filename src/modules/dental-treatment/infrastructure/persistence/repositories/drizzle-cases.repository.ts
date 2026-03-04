import { Injectable } from '@nestjs/common';
import { eq, desc, and, asc, sql } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  IOrthoRepository,
  OrthoCase,
  CaseDetailsDTO,
  CreateCaseInput,
} from '../../../domain/repositories/ortho.repository';
import {
  CaseHistoryDTO,
  TeethMovementRecord,
} from '../../../domain/types/dental.types';

import {
  patients,
  cases,
  treatmentSteps,
  clinics,
  dentists,
} from '@database/schema';

import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { ParsedMovementMap } from '@modules/dental-treatment/application/utils/movement.parser';

@Injectable()
export class DrizzleOrthoRepository
  extends DrizzleBaseRepository
  implements IOrthoRepository
{
  // ==========================================
  // 1. LEGACY MONOLITHIC METHOD
  // (Giữ lại để tương thích ngược, nhưng nên hạn chế dùng)
  // ==========================================

  // ==========================================
  // 2. GRANULAR WRITE METHODS (Atomic Operations)
  // ==========================================

  async createCase(
    data: CreateCaseInput,
    tx?: Transaction,
  ): Promise<{ id: number }> {
    const db = this.getDb(tx);
    const [res] = await db
      .insert(cases)
      .values({
        patientId: data.patientId,
        dentistId: data.dentistId ?? null,
        productType: data.productType as any, // Enum handling
        status: 'PROCESSING',
        notes: data.notes,
        startedAt: new Date(),
      })
      .returning({ id: cases.id });
    return res;
  }

  // ==========================================
  // 3. READ / QUERY METHODS (Type Safe)
  // ==========================================

  async findLatestCaseIdByCode(
    code: string,
    tx?: Transaction,
  ): Promise<string | null> {
    const db = this.getDb(tx);
    // 1. Check if code is numeric Case ID
    if (!isNaN(Number(code))) {
      const caseById = await db.query.cases.findFirst({
        where: eq(cases.id, Number(code)),
        columns: { id: true },
      });
      if (caseById) return String(caseById.id);
    }

    // 2. Check if code is Patient Code
    const result = await db
      .select({ caseId: cases.id })
      .from(cases)
      .innerJoin(patients, eq(cases.patientId, patients.id))
      .where(eq(patients.patientCode, code))
      .orderBy(desc(cases.createdAt))
      .limit(1);

    return result.length > 0 ? String(result[0].caseId) : null;
  }

  async checkCaseBelongsToPatient(
    caseId: string,
    patientCode: string,
    tx?: Transaction,
  ): Promise<boolean> {
    const db = this.getDb(tx);
    if (isNaN(Number(caseId))) return false;
    const result = await db
      .select({ id: cases.id })
      .from(cases)
      .innerJoin(patients, eq(cases.patientId, patients.id))
      .where(
        and(
          eq(cases.id, Number(caseId)),
          eq(patients.patientCode, patientCode),
        ),
      )
      .limit(1);
    return result.length > 0;
  }

  // ✅ OPTIMIZED: Return specific DTO instead of any[]
  async findCasesByPatientCode(
    patientCode: string,
    tx?: Transaction,
  ): Promise<CaseHistoryDTO[]> {
    const db = this.getDb(tx);
    const rows = await db
      .select({
        caseId: cases.id,
        status: cases.status,
        createdAt: cases.createdAt,
        notes: cases.notes,
        productType: cases.productType,
        doctorName: dentists.fullName,
      })
      .from(cases)
      .innerJoin(patients, eq(cases.patientId, patients.id))
      .leftJoin(dentists, eq(cases.dentistId, dentists.id))
      .where(eq(patients.patientCode, patientCode))
      .orderBy(desc(cases.createdAt));

    return rows.map((row) => ({
      caseId: row.caseId,
      status: row.status,
      createdAt: row.createdAt,
      notes: row.notes,
      productType: row.productType,
      doctorName: row.doctorName,
    }));
  }

  async getCaseDetails(
    identifier: string,
    isCaseId: boolean,
    tx?: Transaction,
  ): Promise<CaseDetailsDTO | null> {
    const db = this.getDb(tx);
    const selection = {
      patientName: patients.fullName,
      patientCode: patients.patientCode,
      caseId: cases.id,
      doctorName: dentists.fullName,
      clinicName: clinics.name,
      createdAt: cases.createdAt,
    };

    let queryBuilder;

    if (isCaseId) {
      queryBuilder = db
        .select(selection)
        .from(cases)
        .innerJoin(patients, eq(cases.patientId, patients.id))
        .leftJoin(dentists, eq(cases.dentistId, dentists.id))
        .leftJoin(clinics, eq(patients.clinicId, clinics.id))
        .where(eq(cases.id, Number(identifier)))
        .limit(1);
    } else {
      queryBuilder = db
        .select(selection)
        .from(cases)
        .innerJoin(patients, eq(cases.patientId, patients.id))
        .leftJoin(dentists, eq(cases.dentistId, dentists.id))
        .leftJoin(clinics, eq(patients.clinicId, clinics.id))
        .where(eq(patients.patientCode, identifier))
        .orderBy(desc(cases.createdAt))
        .limit(1);
    }

    const result = await queryBuilder;
    return result[0] ? (result[0] as unknown as CaseDetailsDTO) : null;
  }

  async findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(cases).where(eq(cases.id, id));
    if (!result[0]) return null;

    return {
      id: result[0].id,
      patientId: result[0].patientId,
      status: result[0].status,
      orderId: result[0].orderId,
      createdAt: result[0].createdAt,
    };
  }

  // ==========================================
  // 4. MOVEMENT DATA & STEPS
  // ==========================================

  // ✅ OPTIMIZED: Strict type for teethData
  async updateStepMovementData(
    caseId: string,
    stepIndex: number,
    teethData: TeethMovementRecord,
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);
    const cId = Number(caseId);

    const existingStep = await db
      .select({ id: treatmentSteps.id })
      .from(treatmentSteps)
      .where(
        and(
          eq(treatmentSteps.caseId, cId),
          eq(treatmentSteps.stepIndex, stepIndex),
        ),
      )
      .limit(1);

    if (existingStep.length > 0) {
      await db
        .update(treatmentSteps)
        .set({ teethData: teethData as any }) // Valid cast for JSONB column
        .where(eq(treatmentSteps.id, existingStep[0].id));
    } else {
      await db.insert(treatmentSteps).values({
        caseId: cId,
        stepIndex: stepIndex,
        teethData: teethData as any,
      });
    }
  }

  async deleteStepsByCaseId(caseId: number, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    await db.delete(treatmentSteps).where(eq(treatmentSteps.caseId, caseId));
  }

  async getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]> {
    const db = this.getDb(tx);
    return await db
      .select()
      .from(treatmentSteps)
      .where(eq(treatmentSteps.caseId, caseId))
      .orderBy(asc(treatmentSteps.stepIndex));
  }

  async saveSteps(
    caseId: number,
    stepsMap: ParsedMovementMap,
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);

    if (stepsMap.size === 0) return;

    // 1. Convert Map to Array for Batch Insert
    const valuesToInsert = Array.from(stepsMap.entries()).map(
      ([stepIndex, data]) => ({
        caseId: caseId,
        stepIndex: stepIndex,
        teethData: data as any, // Cast JSONB
        // Mặc định false, có thể update logic parse để lấy thông tin này nếu HTML có
        hasIpr: false, 
        hasAttachments: false,
      }),
    );

    // 2. Bulk Upsert (Insert nếu chưa có, Update nếu trùng caseId + stepIndex)
    await db
      .insert(treatmentSteps)
      .values(valuesToInsert)
      .onConflictDoUpdate({
        target: [treatmentSteps.caseId, treatmentSteps.stepIndex], // Dựa vào Unique Index đã tạo ở step 1
        set: {
          teethData: sql`EXCLUDED.teeth_data`, // Cập nhật dữ liệu mới
        },
      });
  }
}
