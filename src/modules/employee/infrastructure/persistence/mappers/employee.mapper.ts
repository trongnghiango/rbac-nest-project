// src/modules/employee/infrastructure/persistence/mappers/employee.mapper.ts
import { Employee } from '../../../domain/entities/employee.entity';

export class EmployeeMapper {
    /**
     * Chuyển đổi từ Database Record (Snake Case) sang Domain Entity (Camel Case)
     * Tuân thủ: Quy tắc 4.C trong Hiến pháp
     */
    static toDomain(raw: any): Employee | null {
        if (!raw) return null;

        return new Employee({
            id: raw.id,
            organizationId: raw.organization_id,
            userId: raw.userId ? Number(raw.userId) : (raw.user_id ? Number(raw.user_id) : undefined),
            employeeCode: raw.employeeCode || raw.employee_code,
            fullName: raw.fullName || raw.full_name,
            dateOfBirth: raw.dateOfBirth ? new Date(raw.dateOfBirth) : (raw.date_of_birth ? new Date(raw.date_of_birth) : undefined),
            phoneNumber: raw.phoneNumber || raw.phone_number,
            avatarUrl: raw.avatarUrl || raw.avatar_url,
            locationId: raw.locationId || raw.location_id,
            positionId: raw.positionId || raw.position_id,
            managerId: raw.managerId || raw.manager_id,
            joinDate: raw.joinDate ? new Date(raw.joinDate) : (raw.join_date ? new Date(raw.join_date) : undefined),
            createdAt: raw.createdAt || raw.created_at,
            updatedAt: raw.updatedAt || raw.updated_at,
        });
    }

    /**
     * Chuyển đổi từ Domain Entity sang Database Record để lưu trữ
     */
    static toPersistence(domain: Employee): any {
        return {
            id: domain.id,
            organization_id: domain.organizationId,
            user_id: domain.userId,
            employee_code: domain.employeeCode,
            full_name: domain.fullName,
            date_of_birth: domain.dateOfBirth ? domain.dateOfBirth.toISOString().split('T')[0] : null,
            phone_number: domain.phoneNumber,
            avatar_url: domain.avatarUrl,
            location_id: domain.locationId,
            position_id: domain.positionId,
            manager_id: domain.managerId,
            join_date: domain.joinDate ? domain.joinDate.toISOString().split('T')[0] : null,
            updated_at: new Date(),
        };
    }
}
