// src/modules/crm/infrastructure/mappers/assignment.mapper.ts
// Hãy đảm bảo path này trỏ đúng vào file bạn vừa tạo ở bước trước
import { ServiceAssignment } from '../../domain/entities/service-assignment.entity';
export class AssignmentMapper {
    static toDomain(raw: any): ServiceAssignment | null {
        if (!raw) return null;
        return new ServiceAssignment(
            raw.id,
            raw.organizationId,
            raw.employeeId,
            raw.role,
            raw.assignedAt,
        );
    }

    static toPersistence(domain: ServiceAssignment) {
        return {
            id: domain.id,
            organizationId: domain.organizationId,
            employeeId: domain.employeeId,
            role: domain.role,
            assignedAt: domain.assignedAt,
        };
    }
}
