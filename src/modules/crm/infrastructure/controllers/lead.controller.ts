// src/modules/crm/infrastructure/controllers/lead.controller.ts
import { Controller, Post, Body, Param, UseGuards, ParseIntPipe } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody, ApiParam } from '@nestjs/swagger';
import { LeadWorkflowService } from '../../application/services/lead-workflow.service';
import { LeadIntakeService } from '../../application/services/lead-intake.service';
import { CloseLeadRequestDto } from '@modules/crm/infrastructure/dtos/close-lead.request.dto';
import { IntelligentIntakeRequestDto } from '@modules/crm/infrastructure/dtos/intelligent-intake.request.dto';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '@modules/rbac/infrastructure/guards/permission.guard';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';

@ApiTags('CRM (Quản lý Khách hàng & Bán hàng)')
@ApiBearerAuth()
@Controller('crm/leads')
@UseGuards(JwtAuthGuard, PermissionGuard) // Có thể thêm @Permissions('lead:manage') sau này
export class LeadController {
    constructor(
        private readonly leadWorkflowService: LeadWorkflowService,
        private readonly leadIntakeService: LeadIntakeService
    ) { }

    @Post(':id/won')
    @ApiOperation({
        summary: 'Chốt Hợp Đồng (Close Lead as WON)',
        description: 'Nút bấm thần thánh: Chuyển trạng thái Lead thành WON, nâng cấp danh tính khách hàng thành ENTERPRISE, tạo Hợp đồng và gán Team phục vụ trong cùng 1 Transaction.'
    })
    @ApiParam({ name: 'id', description: 'ID của Lead cần chốt', example: 1 })
    @ApiBody({ type: CloseLeadRequestDto })
    @ApiResponse({ status: 201, description: 'Chốt hợp đồng thành công.' })
    @ApiResponse({ status: 400, description: 'Lỗi logic: Lead đã WON hoặc không tìm thấy.' })
    async closeLead(
        @Param('id', ParseIntPipe) leadId: number,
        @Body() dto: CloseLeadRequestDto,
        @CurrentUser() user: any
    ) {
        // Gọi thẳng vào Use Case Orchestrator mà ta đã định nghĩa
        return this.leadWorkflowService.closeLeadAsWon({
            leadId: leadId,
            contractNumber: dto.contractNumber,
            feeAmount: dto.feeAmount,
            serviceType: dto.serviceType,
            taxCode: dto.taxCode,
            newCompanyName: dto.newCompanyName,
            teamAssignments: dto.teamAssignments,
            actorId: user.userId,
            actorName: user.username,
        });
    }

    @Post('intake')
    @ApiOperation({
        summary: 'Tiếp nhận Lead Thông minh (Quick Intake)',
        description: 'Tự động kiểm tra khách hàng cũ qua SĐT. Nếu mới, tự động tạo Contact + Org + Lead. Nếu cũ, chỉ tạo Lead mới gắn vào Org hiện tại.'
    })
    @ApiBody({ type: IntelligentIntakeRequestDto })
    async intelligentIntake(
        @Body() dto: IntelligentIntakeRequestDto,
        @CurrentUser() user: any
    ) {
        return this.leadIntakeService.intelligentIntake({
            ...dto,
            assignedToId: dto.assignedToId || user.userId, // Mặc định gán cho chính người tạo nếu không có chỉ định
        });
    }
}
