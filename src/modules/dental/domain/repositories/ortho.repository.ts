import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { CaseHistoryDTO, TeethMovementRecord } from '../types/dental.types';

// ==========================================
// 1. DATA TYPES (ENTITIES & DTOs)
// ==========================================

export interface OrthoCase {
  id: number;
  orderId?: string | null;
  patientId: number;
  status: string | null;
  createdAt: Date | null;
}

// DTO cho hàm createFullCase cũ (Monolithic)
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

// DTO trả về chi tiết Case cho Frontend
export interface CaseDetailsDTO {
  patientName: string;
  patientCode: string;
  caseId: number;
  doctorName?: string;
  clinicName?: string;
  createdAt: Date;
}

// ==========================================
// 2. INPUT TYPES FOR REFACTORING (GRANULAR)
// ==========================================

export interface ClinicInput {
  name: string;
  code: string;
}

export interface DentistInput {
  fullName: string;
  clinicId: number;
}

export interface PatientInput {
  fullName: string;
  patientCode: string;
  clinicId: number;
  gender?: any; // Có thể để string hoặc Enum nếu đã import
  dob?: Date;
}

export interface CreateCaseInput {
  patientId: number;
  dentistId?: number | null;
  productType: string; // 'aligner' | 'retainer'
  notes?: string;
}

// ==========================================
// 3. REPOSITORY INTERFACE
// ==========================================

export const IOrthoRepository = Symbol('IOrthoRepository');

export interface IOrthoRepository {
  /**
   * @deprecated Logic này nên chuyển lên Service Layer dùng Transaction Manager.
   * Giữ lại để tương thích ngược nếu cần.
   */
  createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string>;

  // --- GRANULAR METHODS (Phục vụ Refactor Service) ---

  // Clinic
  findClinicByCode(
    code: string,
    tx?: Transaction,
  ): Promise<{ id: number } | null>;
  createClinic(data: ClinicInput, tx?: Transaction): Promise<{ id: number }>;

  // Dentist
  findDentist(
    name: string,
    clinicId: number,
    tx?: Transaction,
  ): Promise<{ id: number } | null>;
  createDentist(data: DentistInput, tx?: Transaction): Promise<{ id: number }>;

  // Patient (Thay thế hàm legacy findPatientByCode trả về any)
  findPatientByCode(
    code: string,
    tx?: Transaction,
  ): Promise<{ id: number } | null>;
  createPatient(data: PatientInput, tx?: Transaction): Promise<{ id: number }>;

  // Case (Thay thế hàm legacy createCase trả về any)
  createCase(data: CreateCaseInput, tx?: Transaction): Promise<{ id: number }>;

  // --- QUERY / READ METHODS ---

  findLatestCaseIdByCode(
    code: string,
    tx?: Transaction,
  ): Promise<string | null>;

  checkCaseBelongsToPatient(
    caseId: string,
    patientCode: string,
    tx?: Transaction,
  ): Promise<boolean>;

  // ✅ UPDATED: Trả về CaseHistoryDTO[] thay vì any[]
  findCasesByPatientCode(
    patientCode: string,
    tx?: Transaction,
  ): Promise<CaseHistoryDTO[]>;

  getCaseDetails(
    identifier: string,
    isCaseId: boolean,
    tx?: Transaction,
  ): Promise<CaseDetailsDTO | null>;

  getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]>;

  findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null>;

  // --- MOVEMENT DATA & STEPS ---

  // ✅ UPDATED: teethData sử dụng Type rõ ràng thay vì any
  updateStepMovementData(
    caseId: string,
    stepIndex: number,
    teethData: TeethMovementRecord,
    tx?: Transaction,
  ): Promise<void>;

  deleteStepsByCaseId(caseId: number, tx?: Transaction): Promise<void>;

  // Legacy (Optional: có thể xóa nếu không dùng nữa)
  saveSteps(caseId: number, steps: any[], tx?: Transaction): Promise<void>;
}
