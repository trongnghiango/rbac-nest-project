// src/modules/org-structure/application/dtos/org-unit.dto.ts
import { IsString, IsNotEmpty, IsOptional, IsNumber, IsBoolean, IsIn } from 'class-validator';

export class CreateOrgUnitDto {
    @IsOptional()
    @IsNumber()
    parentId?: number;

    @IsNotEmpty()
    @IsString()
    @IsIn(['COMPANY', 'BRANCH', 'DEPARTMENT', 'TEAM'])
    type: string;

    @IsNotEmpty()
    @IsString()
    code: string;

    @IsNotEmpty()
    @IsString()
    name: string;
}

export class UpdateOrgUnitDto {
    @IsOptional()
    @IsString()
    name?: string;

    @IsOptional()
    @IsBoolean()
    isActive?: boolean;

    @IsOptional()
    @IsNumber()
    parentId?: number;
}
