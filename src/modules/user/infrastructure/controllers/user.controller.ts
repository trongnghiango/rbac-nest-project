import {
  Controller,
  Get,
  Param,
  Put,
  Body,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import { UserService } from '../../application/services/user.service';
import { CurrentUser } from '../../../auth/infrastructure/decorators/current-user.decorator';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { User } from '../../domain/entities/user.entity';
import { UpdateProfileDto } from '../dtos/update-profile.dto';
import { ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { PermissionService } from '@modules/rbac/application/services/permission.service';
import { UserResponseDto } from '../dtos/user-response.dto';

@ApiBearerAuth()
@Controller('users')
@UseGuards(JwtAuthGuard)
export class UserController {
  constructor(
    private userService: UserService,
    private permissionService: PermissionService
  ) { }


  @Get('profile')
  async getProfile(@CurrentUser() currentUser: User) {
    if (!currentUser.id) throw new BadRequestException('Invalid User Context');

    const userEntity = await this.userService.getUserById(currentUser.id);
    return UserResponseDto.fromDomain(userEntity); // Map tại đây
  }

  @Get(':id')
  async getUserById(@Param('id') id: number) {
    const userEntity = await this.userService.getUserById(id);
    return UserResponseDto.fromDomain(userEntity); // Map tại đây
  }

  @Put('profile')
  async updateProfile(
    @CurrentUser() user: User,
    @Body() profileData: UpdateProfileDto,
  ) {
    // FIX: User từ Token chắc chắn phải có ID
    if (!user.id) throw new BadRequestException('Invalid User Context');
    const updatedUser = await this.userService.updateUserProfile(user.id, profileData);
    return UserResponseDto.fromDomain(updatedUser);
  }


  @Get('me/permissions')
  @ApiOperation({ summary: 'Lấy danh sách quyền của người dùng hiện tại' })
  async getMyPermissions(@CurrentUser() user: User) {
    if (!user.id) throw new BadRequestException('Invalid User Context');

    // Gọi service để lấy mảng string các quyền
    const permissions = await this.permissionService.getUserPermissions(user.id);

    return {
      userId: user.id,
      username: user.username,
      permissions: permissions
    };
  }
}
