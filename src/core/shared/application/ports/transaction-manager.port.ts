export type Transaction = unknown; // Opaque type

// 1. Token (Runtime Identifier)
export const ITransactionManager = Symbol('ITransactionManager');

// 2. Interface (Type)
export interface ITransactionManager {
  runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T>;
}
