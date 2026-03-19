import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

import { IUserRepository } from '../../../user/domain/repositories/user.repository';
import { AuthenticationService } from '../../application/services/authentication.service'; // 👉 Inject Service
import { JwtPayload } from '@core/shared/types/common.types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    @Inject(IUserRepository) private userRepository: IUserRepository,
    private authService: AuthenticationService, // 👉 Sử dụng AuthService thay vì Repo
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET') || 'secret',
      passReqToCallback: true, // Lấy nguyên Request để tách Token
    });
  }

  async validate(req: Request, payload: JwtPayload) {
    // 1. Trích xuất Raw Token từ Header (Bearer xxxxx)
    const authHeader = req.headers.authorization;
    if (!authHeader) throw new UnauthorizedException('Thiếu Token');
    const token = authHeader.split(' ')[1];

    // 2. 👉 KIỂM TRA BẢO MẬT XUYÊN THẤU (Redis -> Postgres)
    const validUserId = await this.authService.validateTokenAndGetUserId(token);

    // Nếu trả về null tức là token đã bị thu hồi/xóa ở mọi mặt trận
    if (!validUserId) {
      throw new UnauthorizedException('Phiên đăng nhập đã hết hạn hoặc bị thu hồi (Revoked)');
    }

    // 3. Kiểm tra User tồn tại và đang Active (Bảo mật 2 lớp)
    // Lưu ý: Có thể cân nhắc cache luôn thông tin User này ở Redis nếu muốn tối ưu tuyệt đối
    const user = await this.userRepository.findById(validUserId);
    if (!user || !user.isActive) {
      throw new UnauthorizedException('Tài khoản đã bị khóa hoặc không tồn tại');
    }

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      roles: payload.roles || [],
    };
  }
}
