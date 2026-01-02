import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import {
  CreateClinicDto,
  UpdateClinicDto,
} from '../../application/dtos/clinic.dto';

export const IClinicRepository = Symbol('IClinicRepository');

export interface IClinicRepository {
  // Logic cũ (Upload Flow)
  findClinicByCode(
    code: string,
    tx?: Transaction,
  ): Promise<{ id: number } | null>;
  createClinic(
    data: CreateClinicDto,
    tx?: Transaction,
  ): Promise<{ id: number }>;

  // Logic mới (CRUD Management)
  findAll(): Promise<any[]>;
  findById(id: number): Promise<any | null>;
  update(id: number, data: UpdateClinicDto, tx?: Transaction): Promise<void>;
}
