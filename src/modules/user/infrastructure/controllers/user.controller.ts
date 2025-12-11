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

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UserController {
  constructor(private userService: UserService) {}

  @Get('profile')
  async getProfile(@CurrentUser() user: User) {
    // FIX: User từ Token chắc chắn phải có ID
    if (!user.id) throw new BadRequestException('Invalid User Context');
    return this.userService.getUserById(user.id);
  }

  @Put('profile')
  async updateProfile(
    @CurrentUser() user: User,
    @Body() profileData: UpdateProfileDto,
  ) {
    // FIX: User từ Token chắc chắn phải có ID
    if (!user.id) throw new BadRequestException('Invalid User Context');
    return this.userService.updateUserProfile(user.id, profileData);
  }

  @Get(':id')
  async getUserById(@Param('id') id: number) {
    return this.userService.getUserById(id);
  }
}
