import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import {
  CreateDentistDto,
  UpdateDentistDto,
} from '../../application/dtos/dentist.dto';

export const IDentistRepository = Symbol('IDentistRepository');

export interface IDentistRepository {
  // Logic cũ
  findDentist(
    name: string,
    clinicId: number,
    tx?: Transaction,
  ): Promise<{ id: number } | null>;
  createDentist(
    data: CreateDentistDto,
    tx?: Transaction,
  ): Promise<{ id: number }>;

  // Logic mới
  findAll(clinicId?: number): Promise<any[]>;
  findById(id: number): Promise<any | null>;
  update(id: number, data: UpdateDentistDto, tx?: Transaction): Promise<void>;
}
