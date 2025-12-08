import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { RoleService } from '../../application/services/role.service';
import { PermissionService } from '../../application/services/permission.service';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { Permissions } from '../decorators/permission.decorator';

@Controller('rbac/roles')
@UseGuards(JwtAuthGuard)
export class RoleController {
  constructor(
    private roleService: RoleService,
    private permissionService: PermissionService,
  ) {}

  @Get()
  @Permissions('rbac:manage')
  async getAllRoles() {
    return { message: 'Get all roles' };
  }

  @Post('assign')
  @Permissions('rbac:manage')
  async assignRole(@Body() body: { userId: number; roleId: number }) {
    await this.permissionService.assignRole(
      body.userId,
      body.roleId,
      1, // system user id
    );

    return { success: true, message: 'Role assigned' };
  }
}
