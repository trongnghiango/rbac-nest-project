import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsDateString,
  IsNumber,
  IsEmail,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional, PartialType } from '@nestjs/swagger';

export enum Gender {
  Male = 'Male',
  Female = 'Female',
  Other = 'Other',
}

export class CreatePatientDto {
  @ApiProperty({ example: 'Nguyen Van A' })
  @IsString()
  @IsNotEmpty()
  fullName: string;

  @ApiProperty({
    example: 'PAT-2024-001',
    description: 'Mã bệnh nhân (Unique theo Clinic)',
  })
  @IsString()
  @IsNotEmpty()
  patientCode: string;

  @ApiProperty({ example: 1, description: 'ID phòng khám' })
  @IsNumber()
  @IsNotEmpty()
  clinicId: number;

  @ApiPropertyOptional({ enum: Gender, example: Gender.Male })
  @IsOptional()
  @IsEnum(Gender)
  gender?: Gender;

  @ApiPropertyOptional({
    example: '1990-01-01',
    description: 'ISO 8601 Date String',
  })
  @IsOptional()
  @IsDateString()
  birthDate?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  phoneNumber?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  address?: string;
}

export class UpdatePatientDto extends PartialType(CreatePatientDto) {}
