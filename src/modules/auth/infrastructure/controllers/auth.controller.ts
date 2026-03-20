import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Req,
  Ip,
  BadRequestException,
} from '@nestjs/common';
import { AuthenticationService } from '../../application/services/authentication.service';
import { Public } from '../decorators/public.decorator';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { User } from '../../../user/domain/entities/user.entity';
import { ChangePasswordDto, ForgotPasswordDto, LoginDto, RegisterDto, ResetPasswordDto } from '../dtos/auth.dto';
import type { Request } from 'express'; // Import Request
import { ApiBearerAuth } from '@nestjs/swagger';

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

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@CurrentUser() user: User) {
    //
    const data = user.toString()
    return user.toJSON()
  }

  @ApiBearerAuth()
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

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  async changePassword(@CurrentUser() user: User, @Body() dto: ChangePasswordDto) {
    if (!user.id) throw new BadRequestException('Lỗi định danh User');
    await this.authService.changePassword(user.id, dto);
    return { success: true, message: 'Đổi mật khẩu thành công. Vui lòng đăng nhập lại.' };
  }

  @Public() // Không cần đăng nhập
  @Post('forgot-password')
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    await this.authService.forgotPassword(dto.email);
    // Luôn trả về thông báo chung chung để chống Hacker dò email
    return { success: true, message: 'Nếu email tồn tại trong hệ thống, mã OTP đã được gửi đến bạn.' };
  }

  @Public() // Không cần đăng nhập
  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    await this.authService.resetPassword(dto);
    return { success: true, message: 'Đặt lại mật khẩu thành công. Bạn có thể đăng nhập ngay.' };
  }
}
