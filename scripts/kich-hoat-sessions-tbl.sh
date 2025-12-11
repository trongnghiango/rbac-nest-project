#!/bin/bash

# ============================================
# ACTIVATE SESSION STORAGE
# ============================================
BLUE='\033[0;34m'
NC='\033[0m'
echo -e "${BLUE}[INFO] Updating AuthenticationService to use Sessions...${NC}"

cat > src/modules/auth/application/services/authentication.service.ts << 'EOF'
import { Injectable, Inject, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm'; // Import thêm cái này
import { Repository } from 'typeorm';               // Import thêm cái này
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import { PasswordUtil } from '../../../shared/utils/password.util';
import { User } from '../../../user/domain/entities/user.entity';
import { Session } from '../../domain/entities/session.entity'; // Import Session Entity
import { JwtPayload } from '../../../shared/types/common.types';

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject('IUserRepository') private userRepository: IUserRepository,
    // Inject thêm Repository của Session
    @InjectRepository(Session) private sessionRepository: Repository<Session>,
    private jwtService: JwtService,
  ) {}

  async login(credentials: { username: string; password: string; ip?: string; userAgent?: string }): Promise<{ accessToken: string; user: any }> {
    const user = await this.userRepository.findByUsername(credentials.username);

    if (!user || !user.isActive) throw new UnauthorizedException('Invalid credentials');
    if (!user.hashedPassword) throw new UnauthorizedException('Password not set');

    const isValid = await PasswordUtil.compare(credentials.password, user.hashedPassword);
    if (!isValid) throw new UnauthorizedException('Invalid credentials');

    // 1. Tạo JWT Access Token
    const payload: JwtPayload = {
      sub: user.id,
      username: user.username,
      roles: [],
    };
    const accessToken = this.jwtService.sign(payload);

    // 2. LƯU SESSION VÀO DB (Kích hoạt bảng sessions)
    // Tính thời gian hết hạn (ví dụ 1 ngày)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 1);

    const session = this.sessionRepository.create({
      userId: user.id,
      token: accessToken, // Hoặc lưu Refresh Token nếu dùng cơ chế Refresh
      ipAddress: credentials.ip || 'unknown',
      userAgent: credentials.userAgent || 'unknown',
      expiresAt: expiresAt,
      createdAt: new Date(),
    });

    await this.sessionRepository.save(session);

    return {
      accessToken,
      user: user.toJSON(),
    };
  }

  // ... (Các hàm validateUser, register giữ nguyên như cũ)
  async validateUser(payload: JwtPayload): Promise<ReturnType<User['toJSON']> | null> {
    const user = await this.userRepository.findById(payload.sub);

    // NÂNG CAO: Có thể check thêm session trong DB xem còn tồn tại không
    // Nếu admin đã xóa session thì dù token còn hạn cũng trả về null -> Đá user ra

    if (!user || !user.isActive) return null;
    return user.toJSON();
  }

  async register(data: any): Promise<{ accessToken: string; user: any }> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) throw new BadRequestException('User already exists');

    const hashedPassword = await PasswordUtil.hash(data.password);
    const user: any = {
      id: data.id,
      username: data.username,
      email: data.email,
      hashedPassword: hashedPassword,
      fullName: data.fullName,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const savedUser = await this.userRepository.save(user);

    // Khi register xong cũng tạo session luôn
    const payload = { sub: savedUser.id, username: savedUser.username, roles: [] };
    const accessToken = this.jwtService.sign(payload);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 1);

    await this.sessionRepository.save({
        userId: savedUser.id,
        token: accessToken,
        expiresAt: expiresAt,
        createdAt: new Date()
    });

    return { accessToken, user: savedUser.toJSON() };
  }
}
EOF

# Cập nhật Controller để lấy IP và UserAgent
cat > src/modules/auth/infrastructure/controllers/auth.controller.ts << 'EOF'
import { Controller, Post, Body, UseGuards, Get, Req, Ip } from '@nestjs/common';
import { AuthenticationService } from '../../application/services/authentication.service';
import { Public } from '../decorators/public.decorator';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { User } from '../../../user/domain/entities/user.entity';
import { LoginDto, RegisterDto } from '../dtos/auth.dto';
import { Request } from 'express'; // Import Request

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthenticationService) {}

  @Public()
  @Post('login')
  async login(
    @Body() credentials: LoginDto,
    @Ip() ip: string,
    @Req() request: Request // Lấy User Agent từ Request
  ) {
    return this.authService.login({
      ...credentials,
      ip: ip,
      userAgent: request.headers['user-agent']
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
}
EOF

echo "✅ Session Storage activated!"
