// src/modules/crm/infrastructure/persistence/drizzle-contract.repository.ts
import { Injectable, Inject } from '@nestjs/common';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { IContractRepository } from '../../domain/repositories/contract.repository';
import { Contract } from '../../domain/entities/contract.entity';
import { ContractMapper } from '../mappers/contract.mapper';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';

@Injectable()
export class DrizzleContractRepository extends DrizzleBaseRepository implements IContractRepository {
    constructor(@Inject(DRIZZLE) db: NodePgDatabase<typeof schema>) {
        super(db);
    }

    async create(contract: Contract): Promise<Contract> {
        const data = ContractMapper.toPersistence(contract);
        const [result] = await this.getDb().insert(schema.contracts).values(data as any).returning();
        return ContractMapper.toDomain(result);
    }
}
