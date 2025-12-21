import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export interface OrthoCase {
  id: number;
  orderId: string | null;
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

export const IOrthoRepository = Symbol('IOrthoRepository');

export interface IOrthoRepository {
  findPatientByCode(code: string, tx?: Transaction): Promise<any | null>;
  createPatient(data: any, tx?: Transaction): Promise<any>;
  createCase(data: CreateCaseParams, tx?: Transaction): Promise<OrthoCase>;
  // Method mới mạnh mẽ hơn
  createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string>;

  findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null>;
  saveSteps(caseId: number, steps: any[], tx?: Transaction): Promise<void>;
  getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]>;
}
