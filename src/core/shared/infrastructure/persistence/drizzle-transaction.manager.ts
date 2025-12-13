import { Inject, Injectable } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { DRIZZLE } from '@database/drizzle.provider';
import {
  ITransactionManager,
  Transaction,
} from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleTransactionManager implements ITransactionManager {
  constructor(@Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>) {}

  async runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => {
      return work(tx as unknown as Transaction);
    });
  }
}
