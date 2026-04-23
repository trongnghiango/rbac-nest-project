export interface IRepository<T, ID> {
  findById(id: ID): Promise<T | null>;
  findAll(criteria?: Partial<T>): Promise<T[]>;
  save(entity: T): Promise<T>;
  delete(id: ID): Promise<void>;
  exists(id: ID): Promise<boolean>;
}

export interface IPaginatedRepository<T, ID> extends IRepository<T, ID> {
  findPaginated(
    page: number,
    limit: number,
    criteria?: Partial<T>,
    sort?: { field: string; order: 'ASC' | 'DESC' },
  ): Promise<{ data: T[]; total: number; page: number; totalPages: number }>;
}
