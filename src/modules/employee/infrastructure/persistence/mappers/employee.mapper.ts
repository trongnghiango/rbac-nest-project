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
            organizationId: raw.organizationId,
            userId: raw.userId ? Number(raw.userId) : (raw.userId ? Number(raw.userId) : undefined),
            employeeCode: raw.employeeCode || raw.employeeCode,
            fullName: raw.fullName || raw.fullName,
            dateOfBirth: raw.dateOfBirth ? new Date(raw.dateOfBirth) : (raw.dateOfBirth ? new Date(raw.dateOfBirth) : undefined),
            phoneNumber: raw.phoneNumber || raw.phoneNumber,
            avatarUrl: raw.avatarUrl || raw.avatarUrl,
            locationId: raw.locationId || raw.locationId,
            positionId: raw.positionId || raw.positionId,
            managerId: raw.managerId || raw.managerId,
            joinDate: raw.joinDate ? new Date(raw.joinDate) : (raw.joinDate ? new Date(raw.joinDate) : undefined),
            createdAt: raw.createdAt || raw.createdAt,
            updatedAt: raw.updatedAt || raw.updatedAt,
        });
    }

    /**
     * Chuyển đổi từ Domain Entity sang Database Record để lưu trữ
     */
    static toPersistence(domain: Employee): any {
        return {
            id: domain.id,
            organizationId: domain.organizationId,
            userId: domain.userId,
            employeeCode: domain.employeeCode,
            fullName: domain.fullName,
            dateOfBirth: domain.dateOfBirth ? domain.dateOfBirth.toISOString().split('T')[0] : null,
            phoneNumber: domain.phoneNumber,
            avatarUrl: domain.avatarUrl,
            locationId: domain.locationId,
            positionId: domain.positionId,
            managerId: domain.managerId,
            joinDate: domain.joinDate ? domain.joinDate.toISOString().split('T')[0] : null,
            updatedAt: new Date(),
        };
    }
}
