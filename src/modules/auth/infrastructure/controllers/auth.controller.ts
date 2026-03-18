import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Req,
  Ip,
} from '@nestjs/common';
import { AuthenticationService } from '../../application/services/authentication.service';
import { Public } from '../decorators/public.decorator';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { User } from '../../../user/domain/entities/user.entity';
import { LoginDto, RegisterDto } from '../dtos/auth.dto';
import type { Request } from 'express'; // Import Request

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthenticationService) { }

  @Public()
  @Post('login')
  async login(
    @Body() credentials: LoginDto,
    @Ip() ip: string,
    @Req() request: Request, // Lấy User Agent từ Request
  ) {
    return this.authService.login({
      ...credentials,
      ip: ip,
      userAgent: request.headers['user-agent'],
    });
  }

  @Public()
  @Post('register')
  async register(@Body() data: RegisterDto) {
    return this.authService.register(data);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@CurrentUser() user: User) {
    return { user: user.toJSON() };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Req() request: Request) {
    // Lấy token từ header gửi lên
    const token = request.headers.authorization?.split(' ')[1];
    if (token) {
      await this.authService.logout(token);
    }
    return { success: true, message: 'Đăng xuất thành công' };
  }
}
