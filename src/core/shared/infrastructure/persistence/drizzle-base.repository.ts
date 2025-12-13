import { Inject, Injectable } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { DRIZZLE } from '@database/drizzle.provider';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleBaseRepository {
  constructor(
    @Inject(DRIZZLE) protected readonly db: NodePgDatabase<typeof schema>,
  ) {}

  protected getDb(tx?: Transaction): NodePgDatabase<typeof schema> {
    return tx ? (tx as NodePgDatabase<typeof schema>) : this.db;
  }
}
