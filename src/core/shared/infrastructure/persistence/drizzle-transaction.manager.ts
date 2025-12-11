import { Inject, Injectable } from '@nestjs/common';
import {
  ITransactionManager,
  Transaction,
} from '../../application/ports/transaction-manager.port';
// FIX PATH: 4 cấp ../ để về src, sau đó vào database
import { DRIZZLE } from '../../../../database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../../../database/schema';

@Injectable()
export class DrizzleTransactionManager implements ITransactionManager {
  constructor(@Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>) {}

  async runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => {
      return work(tx as unknown as Transaction);
    });
  }
}
