import { Controller, Get, Post, Body, UseGuards, Inject } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
} from '@nestjs/swagger';
import { RoleService } from '../../application/services/role.service';
import { PermissionService } from '../../application/services/permission.service';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../guards/permission.guard';
import { Permissions } from '../decorators/permission.decorator';
import { RoleResponseDto } from '../dtos/role.dto';
import { AssignRoleDto } from '../dtos/assign-role.dto';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import type { ILogger } from '@core/shared/application/ports/logger.port';
import { PERMISSIONS } from '@modules/rbac/domain/constants/rbac.constants';

@ApiTags('RBAC - Roles')
@ApiBearerAuth()
@Controller('rbac/roles')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class RoleController {
  constructor(
    private roleService: RoleService,
    private permissionService: PermissionService,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) { }

  @ApiOperation({ summary: 'Get all roles with permissions' })
  @ApiResponse({
    status: 200,
    description: 'List of roles',
    type: [RoleResponseDto],
  })
  @Get()
  @Permissions(PERMISSIONS.RBAC_MANAGE)
  async getAllRoles(): Promise<RoleResponseDto[]> {
    const roles = await this.roleService.findAllRoles();
    return roles.map((role) => RoleResponseDto.fromDomain(role));
  }

  @ApiOperation({ summary: 'Assign role to user' })
  @Post('assign')
  @Permissions(PERMISSIONS.RBAC_MANAGE)
  async assignRole(@Body() dto: AssignRoleDto) {
    await this.permissionService.assignRole(dto.userId, dto.roleId, 1);
    return { success: true, message: 'Role assigned' };
  }
}
