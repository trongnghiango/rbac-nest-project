// src/modules/accounting/domain/entities/finote.entity.ts
import { Money } from '@core/shared/domain/value-objects/money.vo';

export interface FinoteProps {
    id?: number;
    code: string;
    type: string; // INCOME | EXPENSE
    sourceOrgId?: number;
    requestedById: number;
    reviewerId?: number;
    title: string;
    amount: Money;
    currency: string;
    category: string;
    description?: string;
    status: string;
    deadlineAt: Date;
    paidAmount?: Money;
    createdAt?: Date;
    updatedAt?: Date;
}

export class Finote {
    public readonly id?: number;
    public readonly code: string;
    public readonly type: string;
    public readonly sourceOrgId?: number;
    public readonly requestedById: number;
    public reviewerId?: number;
    public title: string;
    public amount: Money;
    public category: string;
    public description?: string;
    public status: string;
    public deadlineAt: Date;
    public paidAmount: Money;
    public readonly createdAt?: Date;
    public updatedAt?: Date;

    constructor(props: FinoteProps) {
        this.id = props.id;
        this.code = props.code;
        this.type = props.type;
        this.sourceOrgId = props.sourceOrgId;
        this.requestedById = props.requestedById;
        this.reviewerId = props.reviewerId;
        this.title = props.title;
        this.amount = props.amount;
        this.category = props.category;
        this.description = props.description;
        this.status = props.status || 'PENDING';
        this.deadlineAt = props.deadlineAt;
        this.paidAmount = props.paidAmount || new Money(0);
        this.createdAt = props.createdAt;
        this.updatedAt = props.updatedAt;
    }

    // Logic nghiệp vụ: Xác nhận thanh toán
    recordPayment(paymentAmount: Money) {
        this.paidAmount = this.paidAmount.add(paymentAmount);
        if (this.paidAmount.getAmount() >= this.amount.getAmount()) {
            this.status = 'PAID';
        }
        this.updatedAt = new Date();
    }
}
