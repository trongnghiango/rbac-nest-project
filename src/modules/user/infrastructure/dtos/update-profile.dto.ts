import {
  IsString,
  IsOptional,
  IsUrl,
  IsEnum,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

class SocialLinksDto {
  @ApiPropertyOptional() @IsOptional() @IsUrl() facebook?: string;
  @ApiPropertyOptional() @IsOptional() @IsUrl() telegram?: string;
  @ApiPropertyOptional() @IsOptional() @IsUrl() website?: string;
}

class SettingsDto {
  @ApiPropertyOptional({ enum: ['dark', 'light'] })
  @IsOptional()
  @IsEnum(['dark', 'light'])
  theme: 'dark' | 'light';

  @ApiPropertyOptional()
  @IsOptional()
  notifications: boolean;
}

export class UpdateProfileDto {
  @ApiPropertyOptional({ example: 'I love coding' })
  @IsOptional()
  @IsString()
  bio?: string;

  @ApiPropertyOptional({ example: '1990-01-01' })
  @IsOptional()
  @IsString()
  birthday?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsUrl()
  avatarUrl?: string;

  @ApiPropertyOptional({ enum: ['male', 'female', 'other'] })
  @IsOptional()
  @IsEnum(['male', 'female', 'other'])
  gender?: 'male' | 'female' | 'other';

  @ApiPropertyOptional()
  @IsOptional()
  @ValidateNested()
  @Type(() => SocialLinksDto)
  socialLinks?: SocialLinksDto;

  @ApiPropertyOptional()
  @IsOptional()
  @ValidateNested()
  @Type(() => SettingsDto)
  settings?: SettingsDto;
}
