// src/modules/employee/application/dtos/create-employee.dto.ts
import { IsString, IsNotEmpty, IsNumber, IsOptional } from 'class-validator';

export class CreateEmployeeDto {
    @IsNumber()
    @IsOptional()
    @IsNotEmpty()
    userId?: number;

    @IsString()
    @IsNotEmpty()
    employeeCode: string;

    @IsString()
    @IsNotEmpty()
    fullName: string;

    @IsNumber()
    @IsNotEmpty()
    positionId: number;

    @IsOptional()
    @IsNumber()
    locationId?: number;
}
