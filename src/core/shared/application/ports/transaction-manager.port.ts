export type Transaction = unknown; // Opaque type

export interface ITransactionManager {
  runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T>;
}
