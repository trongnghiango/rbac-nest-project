// src/modules/crm/domain/repositories/contract.repository.ts
import { Contract } from '../entities/contract.entity';

export const IContractRepository = Symbol('IContractRepository');

export interface IContractRepository {
    create(contract: Contract): Promise<Contract>;
}
