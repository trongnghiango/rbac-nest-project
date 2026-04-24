// src/modules/employee/application/dtos/provision-account.dto.ts
import { IsString, IsEmail, IsOptional, MinLength } from 'class-validator';

export class ProvisionAccountDto {
    @IsEmail()
    email: string;

    @IsOptional()
    @IsString()
    @MinLength(4, { message: 'Username phải có ít nhất 4 ký tự' })
    username?: string;
}
