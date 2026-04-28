import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { User } from '@modules/user/domain/entities/user.entity';
import { BootstrapService } from '../../application/services/bootstrap.service';
import { LookupService } from '../../application/services/lookup.service';

@ApiTags('System (Dịch vụ Khung hệ thống)')
@Controller('system')
export class SystemController {
  constructor(
    private readonly bootstrapService: BootstrapService,
    private readonly lookupService: LookupService,
  ) {}
  
  @Get('bootstrap')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'API Khởi tạo Client App (App Bootstrap/Context)',
    description: 'Dành cho Frontend lấy toàn bộ Context (Profile, Configurations, RBAC Flags, Unread notifications) trong 1 lần duy nhất sau khi Login.'
  })
  async getBootstrapContext(@CurrentUser() user: User) {
    return this.bootstrapService.getAppContext(user);
  }

  @Get('lookups')
  @ApiOperation({
    summary: 'Master Data & Enums',
    description: 'Cung cấp toàn bộ danh mục động (Enums) để Frontend render Dropdowns.'
  })
  getLookups() {
    return this.lookupService.getCommonLookups();
  }

  @Get('my-team/summary')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Báo cáo nhanh cho Quản lý (My Team Summary)',
    description: 'Dành cho Sếp soi nhanh các chỉ số quan trọng của đội ngũ (Lead mới, Finote chờ duyệt, hiệu suất nhân viên).'
  })
  async getTeamSummary(@CurrentUser() user: User) {
    return this.bootstrapService.getTeamSummary(user);
  }
}
