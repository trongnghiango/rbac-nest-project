// src/modules/accounting/application/dtos/create-finote.dto.ts
import { IsString, IsNotEmpty, IsNumber, IsOptional, IsEnum, IsDateString } from 'class-validator';

export enum FinoteType {
    INCOME = 'INCOME',
    EXPENSE = 'EXPENSE',
}

export class CreateFinoteDto {
    @IsEnum(FinoteType)
    @IsNotEmpty()
    type: FinoteType;

    @IsString()
    @IsNotEmpty()
    title: string;

    @IsNumber()
    @IsNotEmpty()
    amount: number;

    @IsNumber()
    @IsOptional()
    organizationId?: number;

    @IsString()
    @IsNotEmpty()
    category: string;

    @IsString()
    @IsOptional()
    description?: string;

    @IsDateString()
    @IsNotEmpty()
    deadlineAt: string;
}
