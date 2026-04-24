import { Finote } from '../entities/finote.entity';
import { FinoteAttachment } from '../entities/finote-attachment.entity';

export const IFinoteRepository = Symbol('IFinoteRepository');

export interface IFinoteRepository {
  findById(id: number): Promise<Finote | null>;
  save(finote: Finote): Promise<Finote>;
  addAttachment(attachment: FinoteAttachment): Promise<void>;
}
