import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import {
  CreatePatientDto,
  UpdatePatientDto,
} from '../../application/dtos/patient.dto';

export const IPatientRepository = Symbol('IPatientRepository');

export interface IPatientRepository {
  // Logic cũ
  findPatientByCode(
    code: string,
    tx?: Transaction,
  ): Promise<{ id: number; fullName: string } | null>;
  createPatient(
    data: CreatePatientDto,
    tx?: Transaction,
  ): Promise<{ id: number }>;

  // Logic mới
  findAll(clinicId?: number): Promise<any[]>;
  findById(id: number): Promise<any | null>;
  update(id: number, data: UpdatePatientDto, tx?: Transaction): Promise<void>;
}
