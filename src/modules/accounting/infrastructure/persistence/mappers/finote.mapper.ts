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
            sourceOrgId: raw.source_org_id,
            requestedById: raw.requested_by_id,
            reviewerId: raw.reviewer_id,
            title: raw.title,
            // Vấn đề 4: Chuyển đổi sang Value Object Money
            amount: new Money(Math.round(Number(raw.amount))),
            currency: raw.currency || 'VND',
            category: raw.category,
            description: raw.description,
            status: raw.status,
            deadlineAt: new Date(raw.deadline_at),
            paidAmount: new Money(Math.round(Number(raw.paid_amount || 0))),
            createdAt: raw.created_at,
            updatedAt: raw.updated_at,
        });
    }

    static toPersistence(domain: Finote): any {
        // Khởi tạo object base không có trường id
        const data: any = {
            code: domain.code,
            type: domain.type,
            source_org_id: domain.sourceOrgId,
            requested_by_id: domain.requestedById,
            reviewer_id: domain.reviewerId,
            title: domain.title,
            amount: domain.amount.getAmount().toString(),
            currency: domain.amount.getCurrency(),
            category: domain.category,
            description: domain.description,
            status: domain.status,
            deadline_at: domain.deadlineAt,
            paid_amount: domain.paidAmount.getAmount().toString(),
            updated_at: new Date(),
        };

        // Chỉ gán id nếu tồn tại
        if (domain.id) {
            data.id = domain.id;
        }

        return data;
    }
}
