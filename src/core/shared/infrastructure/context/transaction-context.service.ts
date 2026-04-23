import { Injectable } from '@nestjs/common';
import { AsyncLocalStorage } from 'async_hooks';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class TransactionContextService {
    private static readonly als = new AsyncLocalStorage<Transaction>();

    static run(tx: Transaction, callback: () => Promise<any>): Promise<any> {
        return this.als.run(tx, callback);
    }

    static getTx(): Transaction | undefined {
        return this.als.getStore();
    }
}