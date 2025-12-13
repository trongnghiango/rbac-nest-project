import { Controller, Get, Inject, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../../rbac/infrastructure/guards/permission.guard';
import { Permissions } from '../../rbac/infrastructure/decorators/permission.decorator';
import { Public } from '../../auth/infrastructure/decorators/public.decorator';
import { CurrentUser } from '../../auth/infrastructure/decorators/current-user.decorator';
import { ApiBearerAuth } from '@nestjs/swagger';
import type { ILogger } from '@core/shared/application/ports/logger.port';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';

@Controller('test')
@ApiBearerAuth()
export class TestController {
  constructor(@Inject(LOGGER_TOKEN) private readonly logger: ILogger) {}

  @Public()
  @Get('health')
  healthCheck() {
    this.logger.info('ciquan');
    return {
      status: 'OK',
      timestamp: new Date(),
      service: 'RBAC System',
      version: '1.0.0',
    };
  }

  @Get('protected')
  @UseGuards(JwtAuthGuard)
  protectedRoute(@CurrentUser() user: any) {
    return {
      message: 'This is a protected route',
      user: {
        id: user.id,
        username: user.username,
        roles: user.roles,
      },
    };
  }

  @Get('admin-only')
  @UseGuards(JwtAuthGuard, PermissionGuard)
  @Permissions('rbac:manage')
  adminOnly(@CurrentUser() user: any) {
    return {
      message: 'This is admin-only route',
      user: {
        id: user.id,
        username: user.username,
      },
    };
  }

  @Get('user-management')
  @UseGuards(JwtAuthGuard, PermissionGuard)
  @Permissions('user:manage')
  userManagement(@CurrentUser() user: any) {
    return {
      message: 'You have user management permission',
      user: {
        id: user.id,
        username: user.username,
      },
    };
  }
}
