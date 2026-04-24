// src/modules/crm/application/dtos/close-lead.dto.ts
import { IsString, IsNotEmpty, IsNumber, IsOptional, IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class TeamAssignmentDto {
    @IsNumber()
    @IsNotEmpty()
    employeeId: number;

    @IsString()
    @IsNotEmpty()
    role: string;
}

export class CloseLeadDto {
    @IsString()
    @IsNotEmpty()
    contractNumber: string;

    @IsNumber()
    @IsNotEmpty()
    feeAmount: number;

    @IsString()
    @IsNotEmpty()
    serviceType: string;

    @IsOptional()
    @IsString()
    taxCode?: string;

    @IsOptional()
    @IsString()
    newCompanyName?: string;

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
