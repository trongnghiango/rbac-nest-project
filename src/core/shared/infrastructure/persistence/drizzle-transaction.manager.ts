import { Inject, Injectable } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { DRIZZLE } from '@database/drizzle.provider';
import {
  ITransactionManager,
  Transaction,
} from '@core/shared/application/ports/transaction-manager.port';
import { TransactionContextService } from '../context/transaction-context.service';

@Injectable()
export class DrizzleTransactionManager implements ITransactionManager {
  constructor(@Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>) { }

  async runInTransaction<T>(work: () => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => {
      return TransactionContextService.run(tx as unknown as Transaction, async () => {
        return await work();
      });
    });
  }
}
