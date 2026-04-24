// src/modules/accounting/domain/entities/finote.entity.spec.ts
import { Finote, FinoteItem } from './finote.entity';
import { Money } from '@core/shared/domain/value-objects/money.vo';

describe('Finote Entity', () => {
    it('nên tính toán đúng tổng tiền và VAT từ danh sách Items', () => {
        const item1 = new FinoteItem({
            description: 'Phí dịch vụ kế toán',
            amount: new Money(1000000),
            vatRate: 10,
            vatAmount: new Money(100000),
            totalAmount: new Money(1100000),
        });

        const item2 = new FinoteItem({
            description: 'Phí phát sinh thay đổi GPKD',
            amount: new Money(500000),
            vatRate: 8,
            vatAmount: new Money(40000),
            totalAmount: new Money(540000),
        });

        const finote = new Finote({
            code: 'FN-TEST-001',
            type: 'INCOME',
            title: 'Hóa đơn tháng 04',
            totalAmount: new Money(0), // Sẽ được tính lại
            currency: 'VND',
            requestedById: 1,
            status: 'PENDING',
            deadlineAt: new Date(),
            items: [item1, item2]
        });

        finote.recalculateTotals();

        // Tổng cộng: 1.100.000 + 540.000 = 1.640.000
        expect(finote.totalAmount.getAmount()).toBe(1640000);
        // Tổng VAT: 100.000 + 40.000 = 140.000
        expect(finote.totalVat.getAmount()).toBe(140000);
    });

    it('nên cập nhật trạng thái thanh toán chính xác (PAID / PARTIALLY_PAID)', () => {
        const finote = new Finote({
            code: 'FN-TEST-002',
            type: 'INCOME',
            title: 'Hợp đồng trọn gói',
            totalAmount: new Money(10000000),
            currency: 'VND',
            requestedById: 1,
            status: 'PENDING',
            deadlineAt: new Date(),
        });

        // 1. Trả một phần (3 triệu)
        finote.recordPayment(new Money(3000000));
        expect(finote.status).toBe('PARTIALLY_PAID');
        expect(finote.paidAmount.getAmount()).toBe(3000000);

        // 2. Trả nốt phần còn lại (7 triệu)
        finote.recordPayment(new Money(7000000));
        expect(finote.status).toBe('PAID');
    });
});
