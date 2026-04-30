import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsOptional } from 'class-validator';

export class CreateInteractionNoteDto {
    @ApiProperty({ description: 'Nội dung ghi chú, ví dụ: Đã gọi điện lần 1' })
    @IsNotEmpty()
    @IsString()
    content: string;

    @ApiPropertyOptional({ description: 'Phân loại ghi chú (CALL, EMAIL, MEETING...)' })
    @IsOptional()
    @IsString()
    type?: string;

    @ApiPropertyOptional({ description: 'Siêu dữ liệu tùy chỉnh', type: Object })
    @IsOptional()
    metadata?: any;
}
