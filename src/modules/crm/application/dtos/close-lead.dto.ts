// src/modules/crm/application/dtos/close-lead.dto.ts
import { IsString, IsNotEmpty, IsNumber, IsOptional, IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

class TeamAssignmentDto {
    @ApiProperty({ example: 1, description: 'ID của nhân viên (Employee ID)' })
    @IsNumber()
    @IsNotEmpty()
    employeeId: number;

    @ApiProperty({ example: 'LEADER', description: 'Vai trò (LEADER, CHUYEN_VIEN...)' })
    @IsString()
    @IsNotEmpty()
    role: string;
}

export class CloseLeadDto {
    @ApiProperty({ example: 'HD-2026-001', description: 'Số hợp đồng' })
    @IsString()
    @IsNotEmpty()
    contractNumber: string;

    @ApiProperty({ example: 15000000, description: 'Giá trị hợp đồng' })
    @IsNumber()
    @IsNotEmpty()
    feeAmount: number;

    @ApiProperty({ example: 'Kế toán trọn gói', description: 'Loại dịch vụ' })
    @IsString()
    @IsNotEmpty()
    serviceType: string;

    @ApiPropertyOptional({ example: '0312345678', description: 'Mã số thuế (Cập nhật cho KH)' })
    @IsOptional()
    @IsString()
    taxCode?: string;

    @ApiPropertyOptional({ example: 'Công ty TNHH Phần mềm STAX', description: 'Tên pháp nhân chính thức' })
    @IsOptional()
    @IsString()
    newCompanyName?: string;

    @ApiPropertyOptional({ type: [TeamAssignmentDto], description: 'Danh sách nhân viên phụ trách' })
    @IsOptional()
    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => TeamAssignmentDto)
    teamAssignments?: TeamAssignmentDto[];
}


export interface CloseLeadCommand {
    leadId: number;
    contractNumber: string;
    feeAmount: number;
    serviceType: string;
    taxCode?: string;
    newCompanyName?: string;
    teamAssignments?: { employeeId: number; role: string }[];
}
