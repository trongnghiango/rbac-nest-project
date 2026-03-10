import { IsString, IsOptional, IsNotEmpty, IsEnum } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

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
  @ApiProperty({ example: 'Nguyen Van A' })
  @IsString()
  @IsNotEmpty()
  patientName: string;
  @ApiProperty({ example: 'PAT-12345' })
  @IsString()
  @IsNotEmpty()
  patientCode: string;
  @ApiProperty({ example: 'Smile Dental' })
  @IsString()
  @IsNotEmpty()
  clinicName: string;
  @ApiPropertyOptional({ example: 'Dr. Strange' })
  @IsOptional()
  @IsString()
  doctorName?: string;
  @ApiPropertyOptional({ enum: Gender, example: Gender.Male })
  @IsOptional()
  gender?: any;
  @ApiPropertyOptional({ example: '1990-01-01' }) @IsOptional() dob?: string;
  @ApiPropertyOptional({ enum: ProductType, example: ProductType.Aligner })
  @IsOptional()
  productType?: any;
  @ApiPropertyOptional({ example: 'Ghi chú ca lâm sàng' })
  @IsOptional()
  @IsString()
  notes?: string;
  @ApiPropertyOptional({ example: 'false', description: 'Ghi đè case cũ?' })
  @IsOptional()
  @IsString()
  overwrite?: string;
  @ApiProperty({ type: 'string', format: 'binary' }) file: any;
}
