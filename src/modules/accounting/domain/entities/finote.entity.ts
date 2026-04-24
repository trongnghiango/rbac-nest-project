// src/modules/accounting/domain/entities/finote.entity.ts
import { Money } from '@core/shared/domain/value-objects/money.vo';

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
    type: string; // INCOME | EXPENSE
    sourceOrgId?: number;
    requestedById: number;
    reviewerId?: number;
    title: string;
    totalAmount: Money;
    totalVat?: Money;
    currency: string;
    category?: string; 
    description?: string; 
    status: string;
    deadlineAt: Date;
    items?: FinoteItem[];
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
    public totalAmount: Money;
    public totalVat: Money;
    public category?: string; // Khai báo property ở đây
    public description?: string; // Khai báo property ở đây
    public status: string;
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
        this.reviewerId = props.reviewerId;
        this.title = props.title;
        this.totalAmount = props.totalAmount;
        this.totalVat = props.totalVat || new Money(0);
        this.category = props.category;
        this.description = props.description;
        this.status = props.status || 'PENDING';
        this.deadlineAt = props.deadlineAt;
        this.items = props.items || [];
        this.paidAmount = props.paidAmount || new Money(0);
        this.createdAt = props.createdAt;
        this.updatedAt = props.updatedAt;
    }

    /**
     * Getter cho 'amount' để tương thích với code cũ
     */
    get amount(): Money {
        return this.totalAmount;
    }

    // Logic nghiệp vụ: Tính toán lại tổng tiền từ danh sách items
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

    // Xác nhận gạch nợ
    recordPayment(paymentAmount: Money) {
        this.paidAmount = this.paidAmount.add(paymentAmount);
        if (this.paidAmount.getAmount() >= this.totalAmount.getAmount()) {
            this.status = 'PAID';
        } else if (this.paidAmount.getAmount() > 0) {
            this.status = 'PARTIALLY_PAID';
        }
        this.updatedAt = new Date();
    }
}
