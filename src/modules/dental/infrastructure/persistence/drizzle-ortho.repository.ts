import { Injectable } from '@nestjs/common';
import { eq, asc, InferSelectModel, InferInsertModel } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  IOrthoRepository,
  CreateCaseParams,
  OrthoCase,
} from '../../domain/repositories/ortho.repository';
import {
  patients,
  cases,
  treatmentSteps,
  clinics,
  dentists,
} from '@database/schema/ortho.schema';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

// Type definitions
type PatientRecord = InferSelectModel<typeof patients>;
type NewPatientRecord = InferInsertModel<typeof patients>;
type TreatmentStepRecord = InferSelectModel<typeof treatmentSteps>;

export interface SaveStepInput {
  index: number;
  teethMap: Record<string, unknown>;
  hasIpr?: boolean;
  hasAttachments?: boolean;
}

export interface FullCaseInput {
  patientName: string;
  patientCode: string;
  gender?: 'Male' | 'Female' | 'Other';
  dob?: Date;
  clinicName: string;
  doctorName?: string;
  productType: 'aligner' | 'retainer';
  notes?: string;
}

@Injectable()
export class DrizzleOrthoRepository
  extends DrizzleBaseRepository
  implements IOrthoRepository
{
  // --- Transactional Create Full Case ---
  async createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string> {
     // Hàm này tự quản lý transaction nếu tx chưa được truyền vào
     const runInTx = async (dbTx: any) => {
        // 1. Find or Create Clinic
        let clinicId: number;
        // Giả sử clinicCode được tạo từ tên (slug) hoặc logic riêng. Ở đây lấy tên làm code tạm thời
        const clinicCode = data.clinicName.toUpperCase().replace(/\s+/g, '_').substring(0, 10);

        const existingClinic = await dbTx.select().from(clinics).where(eq(clinics.clinicCode, clinicCode)).limit(1);

        if (existingClinic.length > 0) {
            clinicId = existingClinic[0].id;
        } else {
            const [newClinic] = await dbTx.insert(clinics).values({
                name: data.clinicName,
                clinicCode: clinicCode,
            }).returning();
            clinicId = newClinic.id;
        }

        // 2. Find or Create Dentist
        let dentistId: number | null = null;
        if (data.doctorName) {
            const existingDentist = await dbTx.select().from(dentists)
                .where(eq(dentists.fullName, data.doctorName))
                .limit(1); // Logic này hơi đơn giản, thực tế cần check theo clinicId nữa

            if (existingDentist.length > 0) {
                dentistId = existingDentist[0].id;
            } else {
                const [newDentist] = await dbTx.insert(dentists).values({
                    fullName: data.doctorName,
                    clinicId: clinicId,
                }).returning();
                dentistId = newDentist.id;
            }
        }

        // 3. Find or Create Patient
        let patientId: number;
        const existingPatient = await dbTx.select().from(patients).where(eq(patients.patientCode, data.patientCode)).limit(1);

        if (existingPatient.length > 0) {
            patientId = existingPatient[0].id;
            // Optional: Update patient info if needed
        } else {
            const [newPatient] = await dbTx.insert(patients).values({
                fullName: data.patientName,
                patientCode: data.patientCode,
                clinicId: clinicId,
                gender: data.gender,
                birthDate: data.dob ? data.dob.toISOString().split('T')[0] : null,
            }).returning();
            patientId = newPatient.id;
        }

        // 4. Create Case
        const [newCase] = await dbTx.insert(cases).values({
            patientId: patientId,
            dentistId: dentistId,
            productType: data.productType,
            status: 'PROCESSING', // Đang xử lý
            notes: data.notes,
            startedAt: new Date(),
        }).returning();

        return String(newCase.id); // Trả về Case ID (số chuyển thành chuỗi để dùng làm folder name)
     };

     if (tx) {
         return runInTx(tx);
     } else {
         return this.db.transaction(runInTx);
     }
  }

  // --- Implementations cũ (Giữ lại để tương thích Interface cũ nếu cần) ---
  async findPatientByCode(code: string, tx?: Transaction): Promise<PatientRecord | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(patients).where(eq(patients.patientCode, code));
    return result[0] || null;
  }

  async createPatient(data: NewPatientRecord, tx?: Transaction): Promise<PatientRecord> {
    const db = this.getDb(tx);
    const [newPatient] = await db.insert(patients).values(data).returning();
    return newPatient;
  }

  async createCase(data: CreateCaseParams, tx?: Transaction): Promise<OrthoCase> {
      throw new Error("Use createFullCase instead");
  }

  async findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null> {
    const db = this.getDb(tx);
    const result = await db.query.cases.findFirst({
      where: eq(cases.id, id),
      with: { patient: true, dentist: true, steps: true },
    });
    return (result as unknown as OrthoCase) || null;
  }

  async saveSteps(
    caseId: number,
    stepsData: SaveStepInput[],
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);
    if (stepsData.length > 0) {
      await db.delete(treatmentSteps).where(eq(treatmentSteps.caseId, caseId));
      await db.insert(treatmentSteps).values(
        stepsData.map((s) => ({
          caseId,
          stepIndex: s.index,
          teethData: s.teethMap,
          hasIpr: s.hasIpr ?? false,
          hasAttachments: s.hasAttachments ?? false,
        })),
      );
    }
  }

  async getStepsByCaseId(caseId: number, tx?: Transaction): Promise<TreatmentStepRecord[]> {
    const db = this.getDb(tx);
    return await db.select().from(treatmentSteps).where(eq(treatmentSteps.caseId, caseId)).orderBy(asc(treatmentSteps.stepIndex));
  }
}
