import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Finote, FinoteStatus } from '../../domain/entities/finote.entity';
import { ActionableDto, ActionDetailDto } from '@core/shared/infrastructure/dtos/actionable.dto';

export class FinoteResponseDto extends ActionableDto {
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

    // Actionable metadata for UI
    @ApiProperty({ description: 'Các hành động có thể thực hiện trên UI' })
    _actions: Record<string, ActionDetailDto>;

    static fromDomain(entity: Finote, userPermissions: string[] = []): FinoteResponseDto {
        const dto = new FinoteResponseDto();
        dto.id = entity.id!;
        dto.code = entity.code;
        dto.type = entity.type;
        dto.title = entity.title;
        dto.amount = entity.totalAmount.getAmount();
        dto.currency = entity.totalAmount.getCurrency();
        dto.paidAmount = entity.paidAmount.getAmount();
        dto.category = entity.category || '';
        dto.description = entity.description;
        dto.status = entity.status;
        dto.deadlineAt = entity.deadlineAt;
        dto.createdAt = entity.createdAt;

        // Tính toán Matrix hành động chuyên nghiệp
        const isPending = entity.status === FinoteStatus.PENDING;
        const canManage = userPermissions.includes('*') || userPermissions.includes('finote:approve');

        dto._actions = {
            approve: { 
                allowed: isPending && canManage,
                reason: !isPending ? 'Chỉ có thể duyệt phiếu đang chờ' : (!canManage ? 'Bạn không có quyền duyệt' : undefined)
            },
            reject: { 
                allowed: isPending && canManage,
                reason: !isPending ? 'Chỉ có thể từ chối phiếu đang chờ' : undefined
            },
            edit: {
                allowed: isPending,
                reason: !isPending ? 'Không thể sửa phiếu đã được xử lý' : undefined
            }
        };

        return dto;
    }
}
