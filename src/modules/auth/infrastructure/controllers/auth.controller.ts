import { Controller, Post, Body, UseGuards, Get } from '@nestjs/common';
import { AuthenticationService } from '../../application/services/authentication.service';
import { Public } from '../decorators/public.decorator';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { User } from '../../../user/domain/entities/user.entity';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthenticationService) {}

  @Public()
  @Post('login')
  async login(@Body() credentials: { username: string; password: string }) {
    return this.authService.login(credentials);
  }

  @Public()
  @Post('register')
  async register(
    @Body()
    data: {
      id: number;
      username: string;
      password: string;
      email?: string;
      fullName: string;
    },
  ) {
    return this.authService.register(data);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@CurrentUser() user: User) {
    return { user: user.toJSON() };
  }
}
