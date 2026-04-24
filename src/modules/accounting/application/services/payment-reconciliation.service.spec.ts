// src/modules/accounting/application/services/payment-reconciliation.service.spec.ts
import { PaymentReconciliationService } from './payment-reconciliation.service';
import { IAccountingRepository } from '../../domain/repositories/accounting.repository';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { Finote } from '../../domain/entities/finote.entity';
import { Money } from '@core/shared/domain/value-objects/money.vo';
import { BadRequestException } from '@nestjs/common';

describe('PaymentReconciliationService', () => {
    let service: PaymentReconciliationService;
    let mockRepo: jest.Mocked<IAccountingRepository>;
    let mockTxManager: jest.Mocked<ITransactionManager>;

    beforeEach(() => {
        mockRepo = {
            findFinoteById: jest.fn(),
            saveFinote: jest.fn(),
            saveCashTransaction: jest.fn(),
            linkPayment: jest.fn(),
        } as any;

        mockTxManager = {
            runInTransaction: jest.fn((cb) => cb()), // Chạy thẳng callback cho Unit Test
        } as any;

        service = new PaymentReconciliationService(mockRepo, mockTxManager);
    });

    it('nên gạch nợ thành công một dòng tiền cho nhiều hóa đơn', async () => {
        // Giả lập 2 hóa đơn đang nợ
        const finote1 = new Finote({
            id: 101, code: 'FN1', type: 'INCOME', title: 'HĐ 1',
            totalAmount: new Money(10000000), currency: 'VND',
            requestedById: 1, deadlineAt: new Date(), status: 'PENDING'
        });

        const finote2 = new Finote({
            id: 102, code: 'FN2', type: 'INCOME', title: 'HĐ 2',
            totalAmount: new Money(5000000), currency: 'VND',
            requestedById: 1, deadlineAt: new Date(), status: 'PENDING'
        });

        mockRepo.findFinoteById.mockImplementation(async (id) => {
            if (id === 101) return finote1;
            if (id === 102) return finote2;
            return null;
        });

        mockRepo.saveCashTransaction.mockResolvedValue({ id: 999 } as any);

        // THỰC THI: Khách chuyển 15 triệu, trả nốt 2 hóa đơn
        const result = await service.registerAndAllocatePayment(
            {
                amount: 15000000,
                method: 'BANK_TRANSFER',
                date: new Date(),
                recordedBy: 1,
                bankRef: 'FT2026-X'
            },
            [
                { finoteId: 101, amount: 10000000 },
                { finoteId: 102, amount: 5000000 }
            ]
        );

        // KIỂM TRA
        expect(result.cashTransactionId).toBe(999);
        expect(finote1.status).toBe('PAID');
        expect(finote2.status).toBe('PAID');
        expect(mockRepo.linkPayment).toHaveBeenCalledTimes(2);
    });

    it('nên báo lỗi nếu tổng tiền phân bổ lớn hơn số tiền thực tế nhận', async () => {
        await expect(service.registerAndAllocatePayment(
            { amount: 1000000, method: 'CASH', date: new Date(), recordedBy: 1 },
            [
                { finoteId: 101, amount: 800000 },
                { finoteId: 102, amount: 300000 } // Tổng 1.1 triệu > 1 triệu thực tế
            ]
        )).rejects.toThrow(BadRequestException);
    });
});
