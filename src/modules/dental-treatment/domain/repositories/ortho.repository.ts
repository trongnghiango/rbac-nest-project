import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { CaseHistoryDTO, TeethMovementRecord } from '../types/dental.types';
import { ParsedMovementMap } from '@modules/dental-treatment/application/utils/movement.parser';

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

// ❌ Đã xóa interface FullCaseInput (Không còn dùng)

export interface CaseDetailsDTO {
  patientName: string;
  patientCode: string;
  caseId: number;
  doctorName?: string;
  clinicName?: string;
  createdAt: Date;
}

// ==========================================
// 2. INPUT TYPES (Granular)
// ==========================================

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
  // ❌ Đã xóa createFullCase (Deprecated)

  // --- GRANULAR METHODS ---
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
  updateStepMovementData(
    caseId: string,
    stepIndex: number,
    teethData: TeethMovementRecord,
    tx?: Transaction,
  ): Promise<void>;

  deleteStepsByCaseId(caseId: number, tx?: Transaction): Promise<void>;

  // saveSteps(caseId: number, steps: any[], tx?: Transaction): Promise<void>;
  saveSteps(caseId: number, steps: ParsedMovementMap, tx?: Transaction): Promise<void>;
}
