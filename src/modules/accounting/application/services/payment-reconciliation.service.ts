// src/modules/accounting/application/services/payment-reconciliation.service.ts
import { Injectable, Inject, NotFoundException, BadRequestException } from '@nestjs/common';
import { IAccountingRepository } from '../../domain/repositories/accounting.repository';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { Money } from '@core/shared/domain/value-objects/money.vo';
import { CashTransaction } from '../../domain/entities/cash-transaction.entity';
import { FinoteStatus } from '../../domain/entities/finote.entity';
import { AUDIT_LOG_PORT, IAuditLogService } from '@core/shared/application/ports/audit-log.port';

export interface PaymentAllocation {
    finoteId: number;
    amount: number;
}

@Injectable()
export class PaymentReconciliationService {
    constructor(
        @Inject(IAccountingRepository) private readonly accountingRepo: IAccountingRepository,
        @Inject(ITransactionManager) private readonly txManager: ITransactionManager,
        @Inject(AUDIT_LOG_PORT) private readonly auditLog: IAuditLogService,
    ) { }

    /**
     * Nghiệp vụ Chuyên nghiệp: Ghi nhận dòng tiền và gạch nợ hóa đơn
     * @param transactionData Dữ liệu dòng tiền thô (Cash Flow)
     * @param allocations Danh sách các hóa đơn được thanh toán bằng dòng tiền này
     */
    async registerAndAllocatePayment(
        transactionData: {
            amount: number,
            bankRef?: string,
            method: string,
            date: Date,
            note?: string,
            recordedBy: number
        },
        allocations: PaymentAllocation[]
    ) {
        return await this.txManager.runInTransaction(async () => {
            // 1. Tạo dòng tiền thực tế (Cash Flow)
            const cashTx = new CashTransaction({
                type: 'IN',
                amount: new Money(transactionData.amount),
                transactionDate: transactionData.date,
                transactionRef: transactionData.bankRef,
                paymentMethod: transactionData.method,
                note: transactionData.note,
                recordedById: transactionData.recordedBy,
                status: 'COMPLETED'
            });

            const savedCashTx = await this.accountingRepo.saveCashTransaction(cashTx);

            // 2. Kiểm tra tổng tiền phân bổ không được vượt quá số tiền thực nhận
            const totalAllocated = allocations.reduce((sum, a) => sum + a.amount, 0);
            if (totalAllocated > transactionData.amount) {
                throw new BadRequestException('Tổng tiền gạch nợ không được vượt quá số tiền thực nhận trong dòng tiền.');
            }

            // 3. Tiến hành gạch nợ từng hóa đơn (Finote)
            for (const allocation of allocations) {
                const finote = await this.accountingRepo.findFinoteById(allocation.finoteId);
                if (!finote) {
                    throw new NotFoundException(`Không tìm thấy hóa đơn ID: ${allocation.finoteId}`);
                }

                if (finote.status === FinoteStatus.PAID) {
                    throw new BadRequestException(`Hóa đơn ${finote.code} đã được thanh toán hoàn tất (PAID). Không thể gạch nợ thêm.`);
                }

                // Cập nhật số tiền đã trả trong Entity
                finote.recordPayment(new Money(allocation.amount));
                
                // Lưu trạng thái hóa đơn mới
                await this.accountingRepo.saveFinote(finote);

                // Lưu vết móc nối giữa Tiền và Hóa đơn (Audit Trail)
                await this.accountingRepo.linkPayment(finote.id!, savedCashTx.id!, allocation.amount);

                // 4. Ghi Audit Log toàn hệ thống
                this.auditLog.log({
                    action: 'PAYMENT.ALLOCATED',
                    resource: 'finotes',
                    resource_id: finote.id?.toString(),
                    actor_id: transactionData.recordedBy,
                    metadata: {
                        cashTransactionId: savedCashTx.id,
                        amount: allocation.amount,
                        finoteCode: finote.code,
                        bankRef: transactionData.bankRef
                    },
                    severity: 'INFO'
                });
            }

            return {
                cashTransactionId: savedCashTx.id,
                allocatedFinotes: allocations.length,
                remainingBalance: transactionData.amount - totalAllocated
            };
        });
    }
}
