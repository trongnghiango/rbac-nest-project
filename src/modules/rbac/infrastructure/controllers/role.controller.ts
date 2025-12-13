import {Controller, Get, Post, Body, UseGuards, Inject} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiBody, ApiResponse } from '@nestjs/swagger';
import { RoleService } from '../../application/services/role.service';
import { PermissionService } from '../../application/services/permission.service';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../guards/permission.guard';
import { Permissions } from '../decorators/permission.decorator';
import { RoleResponseDto } from '../dtos/role.dto';
import { LOGGER_TOKEN } from "../../../../core/shared/application/ports/logger.port"; // Import DTO
import type { ILogger } from "../../../../core/shared/application/ports/logger.port"; // Import DTO

@ApiTags('RBAC - Roles')
@ApiBearerAuth()
@Controller('rbac/roles')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class RoleController {
  constructor(
    private roleService: RoleService,
    private permissionService: PermissionService,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger
  ) {}

  @ApiOperation({ summary: 'Get all roles with permissions' })
  @ApiResponse({ status: 200, description: 'List of roles', type: [RoleResponseDto] })
  @Get()
  @Permissions('rbac:manage')
  async getAllRoles(): Promise<RoleResponseDto[]> {
    const roles = await this.roleService.findAllRoles();
    this.logger.info('Roles::', roles);
    return roles.map((role) => RoleResponseDto.fromDomain(role));
  }

  @ApiOperation({ summary: 'Assign role to user' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        userId: { type: 'number', example: 1005 },
        roleId: { type: 'number', example: 2 }
      }
    }
  })
  @Post('assign')
  @Permissions('rbac:manage')
  async assignRole(@Body() body: { userId: number; roleId: number }) {
    await this.permissionService.assignRole(
      body.userId,
      body.roleId,
      1,
    );
    return { success: true, message: 'Role assigned' };
  }
}
