import { Injectable } from '@nestjs/common';
import { eq, asc, InferSelectModel, InferInsertModel } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  IOrthoRepository,
  CreateCaseParams,
  OrthoCase,
} from '../../domain/repositories/ortho.repository';
import { patients, cases, treatmentSteps } from '@database/schema/ortho.schema';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

// 1. Định nghĩa Type từ Drizzle Schema
type PatientRecord = InferSelectModel<typeof patients>;
type NewPatientRecord = InferInsertModel<typeof patients>;
type TreatmentStepRecord = InferSelectModel<typeof treatmentSteps>;

// 2. Định nghĩa Interface cho Input của hàm saveSteps
// Điều này giúp TS biết s.index, s.teethMap là gì -> Hết lỗi Unsafe member access
export interface SaveStepInput {
  index: number;
  teethMap: Record<string, unknown>; // Hoặc type cụ thể của JSON teethData
  hasIpr?: boolean;
  hasAttachments?: boolean;
}

@Injectable()
export class DrizzleOrthoRepository
  extends DrizzleBaseRepository
  implements IOrthoRepository
{
  // --- Patient ---
  // Fix lỗi: Thay 'any | null' bằng 'PatientRecord | null'
  async findPatientByCode(
    code: string,
    tx?: Transaction,
  ): Promise<PatientRecord | null> {
    const db = this.getDb(tx);
    const result = await db
      .select()
      .from(patients)
      .where(eq(patients.patientCode, code));
    return result[0] || null;
  }

  // Fix lỗi: Thay data: any bằng NewPatientRecord
  async createPatient(
    data: NewPatientRecord,
    tx?: Transaction,
  ): Promise<PatientRecord> {
    const db = this.getDb(tx);
    const [newPatient] = await db.insert(patients).values(data).returning();
    return newPatient;
  }

  // --- Case ---
  async createCase(
    data: CreateCaseParams,
    tx?: Transaction,
  ): Promise<OrthoCase> {
    const db = this.getDb(tx);
    const [newCase] = await db
      .insert(cases)
      .values({
        patientId: data.patientId,
        dentistId: data.dentistId,
        productType: data.productType,
        status: 'PLANNING',
        scanDate: data.scanDate || new Date(),
      })
      .returning();

    // Map kết quả từ DB sang Domain Entity (OrthoCase)
    // Cần đảm bảo OrthoCase tương thích với kết quả trả về
    return newCase as unknown as OrthoCase;
  }

  async findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null> {
    const db = this.getDb(tx);
    const result = await db.query.cases.findFirst({
      where: eq(cases.id, id),
      with: {
        patient: true,
        dentist: true,
        steps: true,
      },
    });
    return (result as unknown as OrthoCase) || null;
  }

  // --- Steps (JSONB Data) ---
  async saveSteps(
    caseId: number,
    stepsData: SaveStepInput[], // ✅ FIX: Dùng Interface cụ thể thay vì any[]
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);

    if (stepsData.length > 0) {
      // Xóa steps cũ
      await db.delete(treatmentSteps).where(eq(treatmentSteps.caseId, caseId));

      // Batch Insert
      // Bây giờ 's' đã có kiểu, không còn bị lỗi ESLint unsafe member access
      await db.insert(treatmentSteps).values(
        stepsData.map((s) => ({
          caseId,
          stepIndex: s.index,
          teethData: s.teethMap,
          hasIpr: s.hasIpr ?? false, // Dùng ?? để an toàn hơn ||
          hasAttachments: s.hasAttachments ?? false,
        })),
      );
    }
  }

  // Fix lỗi: Thay Promise<any[]> bằng Promise<TreatmentStepRecord[]>
  async getStepsByCaseId(
    caseId: number,
    tx?: Transaction,
  ): Promise<TreatmentStepRecord[]> {
    const db = this.getDb(tx);
    return await db
      .select()
      .from(treatmentSteps)
      .where(eq(treatmentSteps.caseId, caseId))
      .orderBy(asc(treatmentSteps.stepIndex));
  }
}
