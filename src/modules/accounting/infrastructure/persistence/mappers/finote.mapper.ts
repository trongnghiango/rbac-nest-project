// src/modules/accounting/infrastructure/persistence/mappers/finote.mapper.ts
import { Finote } from '../../../domain/entities/finote.entity';
import { Money } from '@core/shared/domain/value-objects/money.vo';

export class FinoteMapper {
    static toDomain(raw: any): Finote | null {
        if (!raw) return null;

        return new Finote({
            id: raw.id,
            code: raw.code,
            type: raw.type,
            sourceOrgId: raw.sourceOrgId,
            requestedById: raw.requestedById,
            reviewerId: raw.reviewerId,
            title: raw.title,
            // Sử dụng totalAmount thay cho amount cũ
            totalAmount: new Money(Math.round(Number(raw.totalAmount || 0))),
            totalVat: new Money(Math.round(Number(raw.totalVat || 0))),
            currency: raw.currency || 'VND',
            category: raw.category,
            description: raw.description,
            status: raw.status,
            deadlineAt: new Date(raw.deadline_at),
            // Hệ thống mới gạch nợ qua payments, nhưng ta vẫn giữ paidAmount để tương thích
            paidAmount: new Money(Math.round(Number(raw.paid_amount || 0))),
            createdAt: raw.createdAt,
            updatedAt: raw.updatedAt,
        });
    }

    static toPersistence(domain: Finote): any {
        const data: any = {
            code: domain.code,
            type: domain.type,
            sourceOrgId: domain.sourceOrgId,
            requestedById: domain.requestedById,
            reviewerId: domain.reviewerId,
            title: domain.title,
            totalAmount: domain.totalAmount.getAmount().toString(),
            totalVat: domain.totalVat.getAmount().toString(),
            currency: domain.totalAmount.getCurrency(),
            category: domain.category,
            description: domain.description,
            status: domain.status,
            deadline_at: domain.deadlineAt,
            updatedAt: new Date(),
        };

        if (domain.id) {
            data.id = domain.id;
        }

        return data;
    }
}
