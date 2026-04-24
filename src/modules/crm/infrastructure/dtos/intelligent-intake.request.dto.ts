// src/modules/crm/infrastructure/dtos/intelligent-intake.request.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsOptional, IsEmail, IsPhoneNumber } from 'class-validator';

export class IntelligentIntakeRequestDto {
    @ApiProperty({ description: 'Họ và tên khách hàng', example: 'Nguyễn Văn A' })
    @IsString()
    @IsNotEmpty()
    fullName: string;

    @ApiProperty({ description: 'Số điện thoại liên hệ (Dùng để định danh khách hàng)', example: '0901234567' })
    @IsString()
    @IsNotEmpty()
    phone: string;

    @ApiPropertyOptional({ description: 'Email liên hệ', example: 'khachhang@gmail.com' })
    @IsEmail()
    @IsOptional()
    email?: string;

    @ApiProperty({ description: 'Nhu cầu dịch vụ / Sản phẩm quan tâm', example: 'Tư vấn thành lập công ty trọn gói' })
    @IsString()
    @IsNotEmpty()
    serviceDemand: string;

    @ApiPropertyOptional({ description: 'Nguồn Lead (Zalo, Facebook, Google, ...)', example: 'Zalo' })
    @IsString()
    @IsOptional()
    source?: string;

    @ApiPropertyOptional({ description: 'Ghi chú thêm', example: 'Khách muốn làm gấp trong tuần tới' })
    @IsString()
    @IsOptional()
    notes?: string;

    @ApiPropertyOptional({ description: 'ID nhân viên phụ trách (Nếu để trống sẽ gán cho người tạo)', example: 1 })
    @IsOptional()
    assignedToId?: number;
}
