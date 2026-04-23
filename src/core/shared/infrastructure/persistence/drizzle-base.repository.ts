import { Inject, Injectable } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { DRIZZLE } from '@database/drizzle.provider';
import { TransactionContextService } from '../context/transaction-context.service';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';

@Injectable()
export class DrizzleBaseRepository {
  constructor(
    @Inject(DRIZZLE) protected readonly db: NodePgDatabase<typeof schema>,
    // @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) { }


  protected getDb(): NodePgDatabase<typeof schema> {
    const tx = TransactionContextService.getTx();
    return tx ? (tx as unknown as NodePgDatabase<typeof schema>) : this.db;
  }
}
