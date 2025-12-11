import {
  IsString,
  MinLength,
  IsNumber,
  IsOptional,
  IsEmail,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'superadmin', description: 'Username for login' })
  @IsString()
  username: string;

  @ApiProperty({
    example: 'SuperAdmin123!',
    description: 'Password (min 6 chars)',
  })
  @IsString()
  @MinLength(6)
  password: string;
}

export class RegisterDto {
  @ApiProperty({ example: 12345, description: 'User ID (BigInt)' })
  @IsNumber()
  id: number;

  @ApiProperty({ example: 'newuser', description: 'Unique username' })
  @IsString()
  username: string;

  @ApiProperty({ example: 'StrongP@ss1', description: 'Strong password' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'Nguyen Van A', description: 'Full Name' })
  @IsString()
  fullName: string;

  @ApiPropertyOptional({ example: 'user@example.com' })
  @IsOptional()
  @IsEmail()
  email?: string;
}
