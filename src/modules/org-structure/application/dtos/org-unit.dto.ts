
import { IsString, IsNotEmpty, IsOptional, IsNumber, IsBoolean, IsIn } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateOrgUnitDto {
    @ApiPropertyOptional({
        description: 'ID của phòng ban/đơn vị cha. Nếu để trống, đơn vị này sẽ là Node gốc (VD: Hội đồng quản trị/Tổng công ty).',
        example: 1
    })
    @IsOptional()
    @IsNumber()
    parentId?: number;

    @ApiProperty({
        description: 'Loại hình đơn vị tổ chức. Phải thuộc 1 trong 4 loại đã cho.',
        enum: ['COMPANY', 'BRANCH', 'DEPARTMENT', 'TEAM'],
        example: 'DEPARTMENT'
    })
    @IsNotEmpty()
    @IsString()
    @IsIn(['COMPANY', 'BRANCH', 'DEPARTMENT', 'TEAM'])
    type: string;

    @ApiProperty({
        description: 'Mã định danh duy nhất của phòng ban (viết liền không dấu).',
        example: 'PB-TECH'
    })
    @IsNotEmpty()
    @IsString()
    code: string;

    @ApiProperty({
        description: 'Tên hiển thị của phòng ban/đơn vị.',
        example: 'Phòng Công Nghệ Thông Tin'
    })
    @IsNotEmpty()
    @IsString()
    name: string;
}

export class UpdateOrgUnitDto {
    @ApiPropertyOptional({
        description: 'Tên hiển thị mới của phòng ban.',
        example: 'Phòng Phát triển Phần mềm'
    })
    @IsOptional()
    @IsString()
    name?: string;

    @ApiPropertyOptional({
        description: 'Trạng thái hoạt động. Gửi false để đánh dấu phòng ban đã bị giải thể (không xóa khỏi DB).',
        example: false
    })
    @IsOptional()
    @IsBoolean()
    isActive?: boolean;
}
