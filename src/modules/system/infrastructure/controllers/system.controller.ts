import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { User } from '@modules/user/domain/entities/user.entity';

// Import các Module/Service khác nếu cần, hiện tại mock logic tạm để dựng Endpoint.
import { LeadStage } from '@modules/crm/domain/enums/lead-stage.enum';
import { FinoteType, FinoteStatus } from '@modules/accounting/domain/entities/finote.entity';
import { ContractStatus } from '@modules/crm/domain/entities/contract.entity';
import { OrganizationStatus, OrganizationType } from '@modules/crm/domain/entities/organization.entity';

@ApiTags('System (Dịch vụ Khung hệ thống)')
@Controller('system')
export class SystemController {
  
  @Get('bootstrap')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'API Khởi tạo Client App (App Bootstrap/Context)',
    description: 'Dành cho Frontend lấy toàn bộ Context (Profile, Configurations, RBAC Flags, Unread notifications) trong 1 lần duy nhất sau khi Login.'
  })
  async getBootstrapContext(@CurrentUser() user: User) {
    // Để trả về rbac UI Flags, ta thường mock hoặc load từ PermissionService.
    // Tạm thời trả về context chuẩn
    return {
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.personalInfo?.fullName || user.username,
        avatar: user.personalInfo?.avatarUrl || null,
      },
      configs: {
        theme: 'system',
        language: 'vi-VN',
        timezone: 'Asia/Ho_Chi_Minh',
        currency: 'VND',
        dateFormat: 'DD/MM/YYYY',
      },
      // Thông báo chưa đọc
      notifications: {
        unreadCount: 0 
      },
      // Giả lập RBAC UI Flags (Frontend dùng để toggle UI Menu/Button)
      permissions: {
        canViewDashboard: true,
        canManageLeads: true,
        canManageContracts: true,
        canApproveFinotes: false,
      }
    };
  }

  @Get('lookups')
  @ApiOperation({
    summary: 'Master Data & Enums',
    description: 'Cung cấp toàn bộ danh mục động (Enums) để Frontend render Dropdowns.'
  })
  getLookups() {
    // Trả về Enums dưới mạng Key-Value (hoặc list obj) định hình rõ ràng
    return {
      leadStages: Object.values(LeadStage),
      finoteTypes: Object.values(FinoteType),
      finoteStatuses: Object.values(FinoteStatus),
      contractStatuses: Object.values(ContractStatus),
      organizationStatuses: Object.values(OrganizationStatus),
      organizationTypes: Object.values(OrganizationType),
    };
  }
}
