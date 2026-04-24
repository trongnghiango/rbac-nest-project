// src/modules/employee/infrastructure/dtos/create-employee.request.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsNumber, IsOptional } from 'class-validator';
import { CreateEmployeeDto } from '../../application/dtos/create-employee.dto';

export class CreateEmployeeRequestDto extends CreateEmployeeDto {
    @ApiProperty({ description: 'ID của tài khoản User (Định danh)', example: 1 })
    @IsNumber()
    @IsOptional()
    @IsNotEmpty()
    userId?: number;

    @ApiProperty({ description: 'Mã nhân viên', example: 'EMP-001' })
    @IsString()
    @IsNotEmpty()
    employeeCode: string;

    @ApiProperty({ description: 'Họ và tên', example: 'Nguyễn Văn A' })
    @IsString()
    @IsNotEmpty()
    fullName: string;

    @ApiProperty({ description: 'Bổ nhiệm vào Vị trí định biên (ID bảng positions)', example: 5 })
    @IsNumber()
    @IsNotEmpty()
    positionId: number;

    @ApiPropertyOptional({ description: 'Nơi làm việc (ID bảng locations)', example: 1 })
    @IsOptional()
    @IsNumber()
    locationId?: number;
}
