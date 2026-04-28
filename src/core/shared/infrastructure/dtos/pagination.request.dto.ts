import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsString, Min } from 'class-validator';

export class PaginationRequestDto {
  @ApiPropertyOptional({ description: 'Trang hiện tại (Mặc định: 1)', minimum: 1, default: 1 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  readonly page?: number = 1;

  @ApiPropertyOptional({ description: 'Số lượng item mỗi trang (Mặc định: 20)', minimum: 1, default: 20 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  readonly limit?: number = 20;

  @ApiPropertyOptional({ description: 'Sắp xếp theo trường nào (Ví dụ: createdAt)' })
  @IsString()
  @IsOptional()
  readonly sortBy?: string;

  @ApiPropertyOptional({ description: 'Chiều sắp xếp (asc hoặc desc)', enum: ['asc', 'desc'], default: 'desc' })
  @IsString()
  @IsOptional()
  readonly sortDirection?: 'asc' | 'desc' = 'desc';

  @ApiPropertyOptional({ description: 'Từ khóa tìm kiếm chung' })
  @IsString()
  @IsOptional()
  readonly search?: string;
}
