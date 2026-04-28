// src/modules/accounting/infrastructure/controllers/finote.controller.ts
import { Controller, Post, Body, Param, ParseIntPipe, UseGuards, BadRequestException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody, ApiParam } from '@nestjs/swagger';
import { FinoteService } from '../../application/services/finote.service';
import { CreateFinoteDto } from '../../application/dtos/create-finote.dto';
import { CreateFinoteRequestDto } from '../dtos/create-finote.request.dto';
import { RejectFinoteRequestDto } from '../dtos/reject-finote.request.dto';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '@modules/rbac/infrastructure/guards/permission.guard';
import { Permissions } from '@modules/rbac/infrastructure/decorators/permission.decorator';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { User } from '@modules/user/domain/entities/user.entity';
import { FinoteResponseDto } from '../dtos/finote-response.dto'; // <-- Import DTO

@ApiTags('Accounting (Kế toán & Tài chính)')
@ApiBearerAuth()
@Controller('accounting/finotes')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class FinoteController {
    constructor(private readonly finoteService: FinoteService) { }

    @Post(':id/approve')
    @Permissions('finote:approve')
    @ApiOperation({
        summary: 'Phê duyệt phiếu Thu/Chi',
        description: 'Dành cho quản lý (Manager/Admin) xác nhận thông tin phiếu chi/thu là chính xác và cho phép thực hiện thanh toán.'
    })
    @ApiParam({ name: 'id', description: 'ID của Finote', example: 1 })
    async approveFinote(
        @Param('id', ParseIntPipe) id: number,
        @CurrentUser() user: User
    ): Promise<FinoteResponseDto> {
        const employeeId = user.profileContext?.employee?.id;
        if (!employeeId) throw new BadRequestException('Tài khoản chưa có Employee Profile');

        const finote = await this.finoteService.approve(id, employeeId);
        return FinoteResponseDto.fromDomain(finote);
    }

    @Post(':id/reject')
    @Permissions('finote:approve') // Dùng chung quyền approve/reject cấp cao
    @ApiOperation({
        summary: 'Từ chối phiếu Thu/Chi',
        description: 'Dành cho quản lý từ chối phiếu kèm lý do. Trạng thái phiếu sẽ chuyển về REJECTED.'
    })
    @ApiParam({ name: 'id', description: 'ID của Finote', example: 1 })
    @ApiBody({ type: RejectFinoteRequestDto })
    async rejectFinote(
        @Param('id', ParseIntPipe) id: number,
        @Body() dto: RejectFinoteRequestDto,
        @CurrentUser() user: User
    ): Promise<FinoteResponseDto> {
        const employeeId = user.profileContext?.employee?.id;
        if (!employeeId) throw new BadRequestException('Tài khoản chưa có Employee Profile');

        const finote = await this.finoteService.reject(id, employeeId, dto.reason);
        return FinoteResponseDto.fromDomain(finote);
    }

    @Post()
    @Permissions('finote:create')
    @ApiOperation({
        summary: 'Tạo phiếu Thu/Chi (Finote) mới',
        description: 'API tạo phiếu thu (INCOME) hoặc chi (EXPENSE). Sau khi tạo thành công, hệ thống sẽ trigger Event để tự động sinh file PDF.'
    })
    @ApiBody({ type: CreateFinoteRequestDto })
    @ApiResponse({ status: 201, description: 'Tạo phiếu thành công', type: FinoteResponseDto })
    async createFinote(
        @Body() dto: CreateFinoteRequestDto,
        @CurrentUser() user: User
    ): Promise<FinoteResponseDto> {
        if (!user.id) {
            throw new BadRequestException('Không tìm thấy thông tin định danh của người dùng');
        }

        const employeeId = user.profileContext?.employee?.id;
        if (!employeeId) {
            throw new BadRequestException('Tài khoản của bạn chưa được liên kết với Hồ sơ Nhân sự (Employee Profile) nên không thể tạo phiếu!');
        }

        const finoteEntity = await this.finoteService.createFinote(dto, employeeId);
        // Tạm thời mock permissions, sau này lấy từ user object đã qua Guard
        const mockPermissions = ['finote:approve']; 
        return FinoteResponseDto.fromDomain(finoteEntity, mockPermissions);
    }
}
