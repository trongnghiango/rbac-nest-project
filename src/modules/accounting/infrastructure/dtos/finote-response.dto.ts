// src/modules/accounting/infrastructure/dtos/finote-response.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Finote } from '../../domain/entities/finote.entity';

export class FinoteResponseDto {
    @ApiProperty({ example: 1 })
    id: number;

    @ApiProperty({ example: 'INC-2026-0001' })
    code: string;

    @ApiProperty({ example: 'INCOME' })
    type: string;

    @ApiProperty({ example: 'Thu tiền dịch vụ' })
    title: string;

    @ApiProperty({ example: 15000000, description: 'Số tiền (kiểu số nguyên)' })
    amount: number;

    @ApiProperty({ example: 'VND' })
    currency: string;

    @ApiProperty({ example: 'SERVICE_FEE' })
    category: string;

    @ApiPropertyOptional({ example: 'Mô tả chi tiết' })
    description?: string;

    @ApiProperty({ example: 'PENDING' })
    status: string;

    @ApiProperty({ example: '2026-05-01T00:00:00.000Z' })
    deadlineAt: Date;

    @ApiProperty({ example: 0, description: 'Số tiền đã thanh toán' })
    paidAmount: number;

    @ApiPropertyOptional()
    createdAt?: Date;

    static fromDomain(entity: Finote): FinoteResponseDto {
        const dto = new FinoteResponseDto();
        dto.id = entity.id!;
        dto.code = entity.code;
        dto.type = entity.type;
        dto.title = entity.title;

        // ĐÂY LÀ SỰ LỢI HẠI CỦA DTO: 
        // Bóc Value Object 'Money' thành primitive type cho API
        dto.amount = entity.amount.getAmount();
        dto.currency = entity.amount.getCurrency();
        dto.paidAmount = entity.paidAmount.getAmount();

        dto.category = entity.category;
        dto.description = entity.description;
        dto.status = entity.status;
        dto.deadlineAt = entity.deadlineAt;
        dto.createdAt = entity.createdAt;

        return dto;
    }
}
