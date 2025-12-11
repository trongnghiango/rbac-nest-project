import { Injectable } from '@nestjs/common';
import { DataSource, EntityManager } from 'typeorm';
import {
  ITransactionManager,
  Transaction,
} from '../../application/ports/transaction-manager.port';

@Injectable()
export class TypeOrmTransactionManager implements ITransactionManager {
  constructor(private dataSource: DataSource) {}

  async runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
    return this.dataSource.transaction(async (entityManager: EntityManager) => {
      // Ép kiểu EntityManager thành Transaction (unknown) để truyền xuống dưới
      return work(entityManager as unknown as Transaction);
    });
  }
}
