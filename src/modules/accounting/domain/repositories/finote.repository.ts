// src/modules/accounting/domain/repositories/finote.repository.ts
import { Finote } from '../entities/finote.entity';

export const IFinoteRepository = Symbol('IFinoteRepository');

export interface IFinoteRepository {
  findById(id: number): Promise<Finote | null>;
  save(finote: Finote): Promise<Finote>;
  addAttachment(attachment: any): Promise<void>;
}
