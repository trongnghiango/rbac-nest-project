import {
  IsString,
  IsOptional,
  IsEnum,
  IsDateString,
  IsNotEmpty,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum Gender {
  Male = 'Male',
  Female = 'Female',
  Other = 'Other',
}

export enum ProductType {
  Aligner = 'aligner',
  Retainer = 'retainer',
}

export class UploadCaseDto {
  @ApiProperty({
    description: 'Full Name of the Patient',
    example: 'Nguyen Van A',
  })
  @IsString()
  @IsNotEmpty()
  patientName: string;

  @ApiProperty({ description: 'Unique Patient Code', example: 'PAT-12345' })
  @IsString()
  @IsNotEmpty()
  patientCode: string;

  @ApiProperty({ description: 'Gender', enum: Gender, required: false })
  @IsOptional()
  @IsEnum(Gender)
  gender?: Gender;

  @ApiProperty({
    description: 'Date of Birth (ISO)',
    required: false,
    example: '1990-01-01',
  })
  @IsOptional()
  @IsDateString()
  dob?: string;

  @ApiProperty({ description: 'Clinic Name', example: 'Smile Dental' })
  @IsString()
  @IsNotEmpty()
  clinicName: string;

  @ApiProperty({
    description: 'Doctor Name',
    required: false,
    example: 'Dr. House',
  })
  @IsOptional()
  @IsString()
  doctorName?: string;

  @ApiProperty({
    description: 'Product Type',
    enum: ProductType,
    default: ProductType.Aligner,
  })
  @IsOptional()
  @IsEnum(ProductType)
  productType: ProductType = ProductType.Aligner;

  @ApiProperty({ description: 'Additional Notes', required: false })
  @IsOptional()
  @IsString()
  notes?: string;

  @ApiProperty({ type: 'string', format: 'binary' })
  file: any;
}
