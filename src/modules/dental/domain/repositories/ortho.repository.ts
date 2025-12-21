import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

// Định nghĩa kiểu dữ liệu trả về (tạm thời dùng any hoặc type specific)
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

export const IOrthoRepository = Symbol('IOrthoRepository');

export interface IOrthoRepository {
  // Clinic & Patient
  findPatientByCode(code: string, tx?: Transaction): Promise<any | null>;
  createPatient(data: any, tx?: Transaction): Promise<any>;

  // Case
  createCase(data: CreateCaseParams, tx?: Transaction): Promise<OrthoCase>;
  findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null>;

  // Steps (3D Data)
  saveSteps(caseId: number, steps: any[], tx?: Transaction): Promise<void>;
  getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]>;
}
