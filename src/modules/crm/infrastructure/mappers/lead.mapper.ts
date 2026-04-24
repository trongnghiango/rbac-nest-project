import { Lead } from '../../domain/entities/lead.entity';
import { LeadStage } from '../../domain/enums/lead-stage.enum';

export class LeadMapper {
    /**
     * Chuyển từ Database Row (snake_case) sang Domain Entity (camelCase)
     */
    static toDomain(raw: any): Lead | null {
        if (!raw) return null;

        return new Lead({
            id: raw.id,
            organizationId: raw.organization_id,
            contactId: raw.contact_id,
            assignedToId: raw.assigned_to_id,
            createdById: raw.created_by_id,
            title: raw.title,
            serviceNeed: raw.service_need,
            stage: raw.stage as LeadStage,
            source: raw.source,
            estimatedValue: raw.estimated_value,
            note: raw.note,
            expectedCloseDate: raw.expected_close_date,
            closedAt: raw.closed_at,
            lostReason: raw.lost_reason,
            createdAt: raw.created_at,
            updatedAt: raw.updated_at,
        });
    }

    /**
     * Chuyển từ Domain Entity sang Database Row (snake_case)
     */
    static toPersistence(domain: Lead): any {
        return {
            id: domain.id,
            organization_id: domain.organizationId,
            contact_id: domain.contactId,
            assigned_to_id: domain.assignedToId,
            created_by_id: domain.createdById,
            title: domain.title,
            service_need: domain.serviceNeed,
            stage: domain.stage,
            source: domain.source,
            estimated_value: domain.estimatedValue,
            note: domain.note,
            expected_close_date: domain.expectedCloseDate,
            closed_at: domain.closedAt,
            lost_reason: domain.lostReason,
            created_at: domain.createdAt,
            updated_at: domain.updatedAt,
        };
    }
}
