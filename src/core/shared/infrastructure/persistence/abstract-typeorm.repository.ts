import { Repository, ObjectLiteral, EntityManager } from 'typeorm';
import { Transaction } from '../../application/ports/transaction-manager.port';

export abstract class AbstractTypeOrmRepository<T extends ObjectLiteral> {
  protected constructor(protected readonly repository: Repository<T>) {}

  // ✅ LOGIC QUAN TRỌNG NHẤT: Tự động chọn Manager hoặc Default Repo
  protected getRepository(tx?: Transaction): Repository<T> {
    if (tx) {
      const entityManager = tx as EntityManager;
      return entityManager.getRepository(this.repository.target);
    }
    return this.repository;
  }
}
