import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { CaseHistoryDTO, TeethMovementRecord } from '../types/dental.types';
import { ParsedMovementMap } from '@modules/dental-treatment/application/utils/movement.parser';

export interface OrthoCase {
  id: number;
  orderId?: string | null;
  patientId: number;
  status: string | null;
  createdAt: Date | null;
}

export interface CaseDetailsDTO {
  patientName: string;
  patientCode: string;
  caseId: number;
  doctorName?: string;
  clinicName?: string;
  createdAt: Date;
}

export interface CreateCaseInput {
  patientId: number;
  dentistId?: number | null;
  productType: string;
  notes?: string;
}

export const IOrthoRepository = Symbol('IOrthoRepository');

export interface IOrthoRepository {
  // --- WRITE ---
  createCase(data: CreateCaseInput, tx?: Transaction): Promise<{ id: number }>;

  updateStepMovementData(
    caseId: string,
    stepIndex: number,
    teethData: TeethMovementRecord,
    tx?: Transaction,
  ): Promise<void>;

  saveSteps(caseId: number, steps: ParsedMovementMap, tx?: Transaction): Promise<void>;

  deleteStepsByCaseId(caseId: number, tx?: Transaction): Promise<void>;

  // --- READ ---

  // 1. Tìm ID case mới nhất dựa trên Mã Bệnh Nhân (Thay cho findLatestCaseIdByCode)
  findLatestCaseIdByPatientCode(patientCode: string, tx?: Transaction): Promise<number | null>;

  // 2. Lấy chi tiết Case theo ID chính xác (Thay cho getCaseDetails với boolean)
  findCaseDetailById(caseId: number, tx?: Transaction): Promise<CaseDetailsDTO | null>;

  checkCaseBelongsToPatient(caseId: string, patientCode: string, tx?: Transaction): Promise<boolean>;

  findCasesByPatientCode(patientCode: string, tx?: Transaction): Promise<CaseHistoryDTO[]>;

  getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]>;

  findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null>;
}
