import { Transaction } from './transaction-manager.port';

export interface IRepository<T, ID> {
  findById(id: ID, tx?: Transaction): Promise<T | null>;
  findAll(criteria?: Partial<T>, tx?: Transaction): Promise<T[]>;
  // FIX: save trả về Promise<T> thay vì void để đồng bộ với User Repo
  save(entity: T, tx?: Transaction): Promise<T>;
  delete(id: ID, tx?: Transaction): Promise<void>;
  exists(id: ID, tx?: Transaction): Promise<boolean>;
}

export interface IPaginatedRepository<T, ID> extends IRepository<T, ID> {
  findPaginated(
    page: number,
    limit: number,
    criteria?: Partial<T>,
    sort?: { field: string; order: 'ASC' | 'DESC' },
  ): Promise<{ data: T[]; total: number; page: number; totalPages: number }>;
}
