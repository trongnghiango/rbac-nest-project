// src/modules/employee/infrastructure/dtos/employee-response.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Employee } from '../../domain/entities/employee.entity';

export class EmployeeResponseDto {
    @ApiProperty({ example: 1 })
    id: number;

    @ApiProperty({ example: 1, description: 'ID Công ty/Tổ chức' })
    organizationId: number;

    @ApiPropertyOptional({ example: 10, description: 'ID tài khoản đăng nhập (nếu đã cấp)' })
    userId?: number;

    @ApiProperty({ example: 'EMP-001' })
    employeeCode: string;

    @ApiProperty({ example: 'Nguyễn Văn A' })
    fullName: string;

    @ApiPropertyOptional({ example: '1990-01-01' })
    dateOfBirth?: string;

    @ApiPropertyOptional({ example: '0909123456' })
    phoneNumber?: string;

    @ApiPropertyOptional({ example: 'https://...' })
    avatarUrl?: string;

    @ApiPropertyOptional({ example: 1 })
    locationId?: number;

    @ApiPropertyOptional({ example: 5 })
    positionId?: number;

    @ApiPropertyOptional({ example: 2, description: 'ID Quản lý trực tiếp' })
    managerId?: number;

    @ApiPropertyOptional({ example: '2024-01-01' })
    joinDate?: string;

    // Hàm Mapper tĩnh (Static Factory Method)
    static fromDomain(entity: Employee): EmployeeResponseDto {
        const dto = new EmployeeResponseDto();
        // Bắt buộc fallback lỗi undefined nếu Entity chưa có ID (mặc dù fetch từ DB ra chắc chắn có)
        dto.id = entity.id!;
        dto.organizationId = entity.organizationId;
        dto.userId = entity.userId;
        dto.employeeCode = entity.employeeCode;
        dto.fullName = entity.fullName;
        dto.dateOfBirth = entity.dateOfBirth ? entity.dateOfBirth.toISOString().split('T')[0] : undefined;
        dto.phoneNumber = entity.phoneNumber;
        dto.avatarUrl = entity.avatarUrl;
        dto.locationId = entity.locationId;
        dto.positionId = entity.positionId;
        dto.managerId = entity.managerId;
        dto.joinDate = entity.joinDate ? entity.joinDate.toISOString().split('T')[0] : undefined;

        return dto;
    }
}
