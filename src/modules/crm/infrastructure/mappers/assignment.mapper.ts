// src/modules/crm/infrastructure/mappers/assignment.mapper.ts
// Hãy đảm bảo path này trỏ đúng vào file bạn vừa tạo ở bước trước
import { ServiceAssignment } from '../../domain/entities/service-assignment.entity';
export class AssignmentMapper {
    static toDomain(raw: any): ServiceAssignment | null {
        if (!raw) return null;
        return new ServiceAssignment(
            raw.id,
            raw.organization_id,
            raw.employee_id,
            raw.role,
            raw.assigned_at,
        );
    }

    static toPersistence(domain: ServiceAssignment) {
        return {
            id: domain.id,
            organization_id: domain.organizationId,
            employee_id: domain.employeeId,
            role: domain.role,
            assigned_at: domain.assignedAt,
        };
    }
}
