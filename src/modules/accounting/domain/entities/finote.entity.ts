// src/modules/accounting/domain/entities/finote.entity.ts
import { Money } from '@core/shared/domain/value-objects/money.vo';

export enum FinoteType {
    INCOME = 'INCOME',
    EXPENSE = 'EXPENSE',
}

export enum FinoteStatus {
    PENDING = 'PENDING',
    APPROVED = 'APPROVED',
    PAID = 'PAID',
    PARTIALLY_PAID = 'PARTIALLY_PAID',
    CANCELLED = 'CANCELLED',
    REJECTED = 'REJECTED',
}

export interface FinoteItemProps {
    id?: number;
    description: string;
    amount: Money;
    vatRate: number;
    vatAmount: Money;
    totalAmount: Money;
}

export class FinoteItem {
    constructor(public readonly props: FinoteItemProps) {}
}

export interface FinoteProps {
    id?: number;
    code: string;
    type: FinoteType;
    sourceOrgId?: number;
    requestedById: number;
    reviewerId?: number;
    title: string;
    totalAmount: Money;
    totalVat?: Money;
    currency: string;
    category?: string; 
    description?: string; 
    status: FinoteStatus;
    deadlineAt: Date;
    items?: FinoteItem[];
    paidAmount?: Money;
    createdAt?: Date;
    updatedAt?: Date;
}

export class Finote {
    public readonly id?: number;
    public readonly code: string;
    public readonly type: FinoteType;
    public readonly sourceOrgId?: number;
    public readonly requestedById: number;
    private _reviewerId?: number;
    public title: string;
    public totalAmount: Money;
    public totalVat: Money;
    public category?: string;
    public description?: string;
    private _status: FinoteStatus;
    public deadlineAt: Date;
    public items: FinoteItem[];
    public paidAmount: Money;
    public readonly createdAt?: Date;
    public updatedAt?: Date;

    constructor(props: FinoteProps) {
        this.id = props.id;
        this.code = props.code;
        this.type = props.type;
        this.sourceOrgId = props.sourceOrgId;
        this.requestedById = props.requestedById;
        this._reviewerId = props.reviewerId;
        this.title = props.title;
        this.totalAmount = props.totalAmount;
        this.totalVat = props.totalVat || new Money(0);
        this.category = props.category;
        this.description = props.description;
        this._status = props.status || FinoteStatus.PENDING;
        this.deadlineAt = props.deadlineAt;
        this.items = props.items || [];
        this.paidAmount = props.paidAmount || new Money(0);
        this.createdAt = props.createdAt;
        this.updatedAt = props.updatedAt;
    }

    get amount(): Money {
        return this.totalAmount;
    }

    get status(): FinoteStatus {
        return this._status;
    }

    get reviewerId(): number | undefined {
        return this._reviewerId;
    }

    approve(reviewerId: number) {
        if (this._status !== FinoteStatus.PENDING) {
            throw new Error('Chỉ có thể duyệt phiếu đang ở trạng thái PENDING');
        }
        this._status = FinoteStatus.APPROVED;
        this._reviewerId = reviewerId;
        this.updatedAt = new Date();
    }

    reject(reviewerId: number, reason: string) {
        if (this._status !== FinoteStatus.PENDING) {
            throw new Error('Chỉ có thể từ chối phiếu đang ở trạng thái PENDING');
        }
        this._status = FinoteStatus.REJECTED;
        this._reviewerId = reviewerId;
        this.description = `${this.description || ''} [Lý do từ chối: ${reason}]`.trim();
        this.updatedAt = new Date();
    }

    recalculateTotals() {
        let total = 0;
        let vat = 0;
        this.items.forEach(item => {
            total += item.props.totalAmount.getAmount();
            vat += item.props.vatAmount.getAmount();
        });
        this.totalAmount = new Money(total);
        this.totalVat = new Money(vat);
    }

    recordPayment(paymentAmount: Money) {
        this.paidAmount = this.paidAmount.add(paymentAmount);
        if (this.paidAmount.getAmount() >= this.totalAmount.getAmount()) {
            this._status = FinoteStatus.PAID;
        } else if (this.paidAmount.getAmount() > 0) {
            this._status = FinoteStatus.PARTIALLY_PAID;
        }
        this.updatedAt = new Date();
    }
}
