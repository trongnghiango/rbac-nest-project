import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export interface OrthoCase {
  id: number;
  orderId?: string | null;
  patientId: number;
  status: string | null;
  createdAt: Date | null;
}
export interface CreateCaseParams {
  patientId: number;
  dentistId?: number;
  productType: 'aligner' | 'retainer';
  scanDate?: Date;
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
export interface CaseDetailsDTO {
  patientName: string;
  patientCode: string;
  caseId: number;
  doctorName?: string;
  clinicName?: string;
  createdAt: Date;
}

export const IOrthoRepository = Symbol('IOrthoRepository');

export interface IOrthoRepository {
  createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string>;
  findLatestCaseIdByCode(
    code: string,
    tx?: Transaction,
  ): Promise<string | null>;
  checkCaseBelongsToPatient(
    caseId: string,
    patientCode: string,
    tx?: Transaction,
  ): Promise<boolean>;
  findCasesByPatientCode(patientCode: string, tx?: Transaction): Promise<any[]>;
  getCaseDetails(
    identifier: string,
    isCaseId: boolean,
    tx?: Transaction,
  ): Promise<CaseDetailsDTO | null>;
  getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]>;

  // ✅ NEW
  updateStepMovementData(
    caseId: string,
    stepIndex: number,
    teethData: any,
    tx?: Transaction,
  ): Promise<void>;

  // Legacy
  findPatientByCode(code: string, tx?: Transaction): Promise<any | null>;
  createPatient(data: any, tx?: Transaction): Promise<any>;
  createCase(data: any, tx?: Transaction): Promise<any>;
  findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null>;
  saveSteps(caseId: number, steps: any[], tx?: Transaction): Promise<void>;
  deleteStepsByCaseId(caseId: number, tx?: Transaction): Promise<void>;
}
