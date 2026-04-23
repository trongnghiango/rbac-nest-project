// src/core/shared/domain/repositories/sequence.repository.ts
export const ISequenceRepository = Symbol('ISequenceRepository');

export interface ISequenceRepository {
    incrementAndGetNext(prefix: string): Promise<number>;
}
