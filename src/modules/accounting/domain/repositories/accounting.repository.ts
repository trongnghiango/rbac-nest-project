// src/modules/accounting/domain/repositories/accounting.repository.ts
import { Finote, FinoteItem } from '../entities/finote.entity';
import { CashTransaction } from '../entities/cash-transaction.entity';

export const IAccountingRepository = Symbol('IAccountingRepository');

export interface IAccountingRepository {
    // Finotes (Header & Items)
    findFinoteById(id: number): Promise<Finote | null>;
    findFinoteByCode(code: string): Promise<Finote | null>;
    saveFinote(finote: Finote): Promise<Finote>;
    
    // Cash Transactions (Cash Flow)
    saveCashTransaction(transaction: CashTransaction): Promise<CashTransaction>;
    findCashTransactionById(id: number): Promise<CashTransaction | null>;

    // Payment Mapping
    linkPayment(finoteId: number, cashTransactionId: number, amount: number): Promise<void>;
}
