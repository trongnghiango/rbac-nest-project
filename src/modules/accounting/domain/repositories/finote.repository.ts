// src/modules/accounting/domain/repositories/finote.repository.ts
export const IFinoteRepository = Symbol('IFinoteRepository');

export interface IFinoteRepository {
    save(data: any): Promise<any>;
    findById(id: number): Promise<any>;
    addAttachment(data: any): Promise<void>;
}
