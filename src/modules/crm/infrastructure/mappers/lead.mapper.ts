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
        const json = domain.toJSON();
        return {
            id: json.id,
            organization_id: json.organizationId,
            contact_id: json.contactId,
            assigned_to_id: json.assignedToId,
            created_by_id: json.createdById,
            title: json.title,
            service_need: json.serviceNeed,
            stage: json.stage,
            source: json.source,
            estimated_value: json.estimatedValue,
            note: json.note,
            expected_close_date: json.expectedCloseDate,
            closed_at: json.closedAt,
            lost_reason: json.lostReason,
            created_at: json.createdAt,
            updated_at: json.updatedAt,
        };
    }
}
