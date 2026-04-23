// src/core/shared/domain/repositories/sequence.repository.ts
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export const ISequenceRepository = Symbol('ISequenceRepository');

export interface ISequenceRepository {
    incrementAndGetNext(prefix: string): Promise<number>;
}
