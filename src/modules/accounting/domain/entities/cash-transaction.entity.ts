// src/modules/accounting/domain/entities/cash-transaction.entity.ts
import { Money } from '@core/shared/domain/value-objects/money.vo';

export interface CashTransactionProps {
    id?: number;
    type: 'IN' | 'OUT';
    amount: Money;
    transactionDate: Date;
    paymentMethod?: string;
    bankAccount?: string;
    transactionRef?: string;
    note?: string;
    recordedById?: number;
    status: string;
}

export class CashTransaction {
    public readonly id?: number;
    public readonly type: 'IN' | 'OUT';
    public readonly amount: Money;
    public readonly transactionDate: Date;
    public readonly paymentMethod?: string;
    public readonly bankAccount?: string;
    public readonly transactionRef?: string;
    public readonly note?: string;
    public readonly recordedById?: number;
    public status: string;

    constructor(props: CashTransactionProps) {
        this.id = props.id;
        this.type = props.type;
        this.amount = props.amount;
        this.transactionDate = props.transactionDate || new Date();
        this.paymentMethod = props.paymentMethod;
        this.bankAccount = props.bankAccount;
        this.transactionRef = props.transactionRef;
        this.note = props.note;
        this.recordedById = props.recordedById;
        this.status = props.status || 'COMPLETED';
    }
}
