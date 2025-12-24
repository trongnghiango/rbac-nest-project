import { Injectable } from '@nestjs/common';
import { eq, desc, and, asc } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  IOrthoRepository,
  CreateCaseParams,
  OrthoCase,
  FullCaseInput,
  CaseDetailsDTO,
} from '../../domain/repositories/ortho.repository';
import {
  patients,
  cases,
  treatmentSteps,
  clinics,
  dentists,
} from '@database/schema/ortho.schema';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleOrthoRepository
  extends DrizzleBaseRepository
  implements IOrthoRepository
{
  async createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string> {
    const runInTx = async (dbTx: any) => {
      const clinicCode = data.clinicName
        .toUpperCase()
        .replace(/\s+/g, '_')
        .substring(0, 10);

      let clinicId: number;
      const existingClinic = await dbTx
        .select()
        .from(clinics)
        .where(eq(clinics.clinicCode, clinicCode))
        .limit(1);
      if (existingClinic.length > 0) {
        clinicId = existingClinic[0].id;
      } else {
        const [newClinic] = await dbTx
          .insert(clinics)
          .values({
            name: data.clinicName,
            clinicCode: clinicCode,
          })
          .returning();
        clinicId = newClinic.id;
      }

      let dentistId: number | null = null;
      if (data.doctorName) {
        const existingDentist = await dbTx
          .select()
          .from(dentists)
          .where(
            and(
              eq(dentists.fullName, data.doctorName),
              eq(dentists.clinicId, clinicId),
            ),
          )
          .limit(1);
        if (existingDentist.length > 0) {
          dentistId = existingDentist[0].id;
        } else {
          const [newDentist] = await dbTx
            .insert(dentists)
            .values({
              fullName: data.doctorName,
              clinicId: clinicId,
            })
            .returning();
          dentistId = newDentist.id;
        }
      }

      let patientId: number;
      const existingPatient = await dbTx
        .select()
        .from(patients)
        .where(eq(patients.patientCode, data.patientCode))
        .limit(1);
      if (existingPatient.length > 0) {
        patientId = existingPatient[0].id;
      } else {
        const [newPatient] = await dbTx
          .insert(patients)
          .values({
            fullName: data.patientName,
            patientCode: data.patientCode,
            clinicId: clinicId,
            gender: data.gender,
            birthDate: data.dob ? data.dob.toISOString().split('T')[0] : null,
          })
          .returning();
        patientId = newPatient.id;
      }

      const [newCase] = await dbTx
        .insert(cases)
        .values({
          patientId: patientId,
          dentistId: dentistId,
          productType: data.productType,
          status: 'PROCESSING',
          notes: data.notes,
          startedAt: new Date(),
        })
        .returning();

      return String(newCase.id);
    };

    if (tx) return runInTx(tx);
    return this.db.transaction(runInTx);
  }

  // ✅ NEW: Hàm Update Movement Data
  async updateStepMovementData(
    caseId: string,
    stepIndex: number,
    teethData: any,
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);
    const cId = Number(caseId);

    // Kiểm tra xem step đã tồn tại chưa
    const existingStep = await db
      .select()
      .from(treatmentSteps)
      .where(
        and(
          eq(treatmentSteps.caseId, cId),
          eq(treatmentSteps.stepIndex, stepIndex),
        ),
      )
      .limit(1);

    if (existingStep.length > 0) {
      // Update
      await db
        .update(treatmentSteps)
        .set({ teethData: teethData })
        .where(eq(treatmentSteps.id, existingStep[0].id));
    } else {
      // Insert mới (nếu chưa có model nhưng có data trước)
      await db.insert(treatmentSteps).values({
        caseId: cId,
        stepIndex: stepIndex,
        teethData: teethData,
      });
    }
  }

  async getCaseDetails(
    identifier: string,
    isCaseId: boolean,
    tx?: Transaction,
  ): Promise<CaseDetailsDTO | null> {
    const db = this.getDb(tx);
    let selection = {
      patientName: patients.fullName,
      patientCode: patients.patientCode,
      caseId: cases.id,
      doctorName: dentists.fullName,
      clinicName: clinics.name,
      createdAt: cases.createdAt,
    };

    let query;
    if (isCaseId) {
      query = db
        .select(selection)
        .from(cases)
        .innerJoin(patients, eq(cases.patientId, patients.id))
        .leftJoin(dentists, eq(cases.dentistId, dentists.id))
        .leftJoin(clinics, eq(patients.clinicId, clinics.id))
        .where(eq(cases.id, Number(identifier)))
        .limit(1);
    } else {
      query = db
        .select(selection)
        .from(cases)
        .innerJoin(patients, eq(cases.patientId, patients.id))
        .leftJoin(dentists, eq(cases.dentistId, dentists.id))
        .leftJoin(clinics, eq(patients.clinicId, clinics.id))
        .where(eq(patients.patientCode, identifier))
        .orderBy(desc(cases.createdAt))
        .limit(1);
    }
    const result = await query;
    return result[0] || null;
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

  async findLatestCaseIdByCode(
    code: string,
    tx?: Transaction,
  ): Promise<string | null> {
    const db = this.getDb(tx);
    if (!isNaN(Number(code))) {
      const caseById = await db.query.cases.findFirst({
        where: eq(cases.id, Number(code)),
      });
      if (caseById) return String(caseById.id);
    }
    const result = await db
      .select({ caseId: cases.id })
      .from(cases)
      .innerJoin(patients, eq(cases.patientId, patients.id))
      .where(eq(patients.patientCode, code))
      .orderBy(desc(cases.createdAt))
      .limit(1);

    if (result.length > 0) return String(result[0].caseId);
    return null;
  }

  async findCasesByPatientCode(
    patientCode: string,
    tx?: Transaction,
  ): Promise<any[]> {
    const db = this.getDb(tx);
    return await db
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
  }

  async getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]> {
    const db = this.getDb(tx);
    // ✅ QUAN TRỌNG: Select luôn teethData
    return await db
      .select()
      .from(treatmentSteps)
      .where(eq(treatmentSteps.caseId, caseId))
      .orderBy(asc(treatmentSteps.stepIndex));
  }

  // Legacy
  async findPatientByCode(code: string, tx?: Transaction): Promise<any | null> {
    return null;
  }
  async createPatient(data: any, tx?: Transaction): Promise<any> {
    return null;
  }
  async createCase(
    data: CreateCaseParams,
    tx?: Transaction,
  ): Promise<OrthoCase> {
    throw new Error('');
  }
  async findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null> {
    return null;
  }
  async saveSteps(
    caseId: number,
    steps: any[],
    tx?: Transaction,
  ): Promise<void> {}
}
