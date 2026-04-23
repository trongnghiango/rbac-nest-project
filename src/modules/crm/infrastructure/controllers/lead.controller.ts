// src/modules/crm/infrastructure/controllers/lead.controller.ts
import { Controller, Post, Body, Param, UseGuards, ParseIntPipe } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody, ApiParam } from '@nestjs/swagger';
import { LeadWorkflowService } from '../../application/services/lead-workflow.service';
import { CloseLeadDto } from '../../application/dtos/close-lead.dto';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '@modules/rbac/infrastructure/guards/permission.guard';

@ApiTags('CRM (Quản lý Khách hàng & Bán hàng)')
@ApiBearerAuth()
@Controller('crm/leads')
@UseGuards(JwtAuthGuard, PermissionGuard) // Có thể thêm @Permissions('lead:manage') sau này
export class LeadController {
    constructor(private readonly leadWorkflowService: LeadWorkflowService) { }

    @Post(':id/won')
    @ApiOperation({
        summary: 'Chốt Hợp Đồng (Close Lead as WON)',
        description: 'Nút bấm thần thánh: Chuyển trạng thái Lead thành WON, nâng cấp danh tính khách hàng thành ENTERPRISE, tạo Hợp đồng và gán Team phục vụ trong cùng 1 Transaction.'
    })
    @ApiParam({ name: 'id', description: 'ID của Lead cần chốt', example: 1 })
    @ApiBody({ type: CloseLeadDto })
    @ApiResponse({ status: 201, description: 'Chốt hợp đồng thành công.' })
    @ApiResponse({ status: 400, description: 'Lỗi logic: Lead đã WON hoặc không tìm thấy.' })
    async closeLead(
        @Param('id', ParseIntPipe) leadId: number,
        @Body() dto: CloseLeadDto
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
        });
    }
}
