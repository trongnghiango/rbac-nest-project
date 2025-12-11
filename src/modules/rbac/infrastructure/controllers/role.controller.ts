import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiBody } from '@nestjs/swagger';
import { RoleService } from '../../application/services/role.service';
import { PermissionService } from '../../application/services/permission.service';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../guards/permission.guard';
import { Permissions } from '../decorators/permission.decorator';

@ApiTags('RBAC - Roles')
@ApiBearerAuth()
@Controller('rbac/roles')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class RoleController {
  constructor(
    private roleService: RoleService,
    private permissionService: PermissionService,
  ) {}

  @ApiOperation({ summary: 'Get all roles (Requires rbac:manage)' })
  @Get()
  @Permissions('rbac:manage')
  async getAllRoles() {
    return { message: 'Get all roles' };
  }

  @ApiOperation({ summary: 'Assign role to user' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        userId: { type: 'number', example: 1005 },
        roleId: { type: 'number', example: 2 },
      },
    },
  })
  @Post('assign')
  @Permissions('rbac:manage')
  async assignRole(@Body() body: { userId: number; roleId: number }) {
    await this.permissionService.assignRole(body.userId, body.roleId, 1);
    return { success: true, message: 'Role assigned' };
  }
}
