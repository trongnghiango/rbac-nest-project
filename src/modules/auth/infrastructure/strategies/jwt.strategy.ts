import { Injectable, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
// FIX IMPORT
import { IUserRepository } from '../../../user/domain/repositories/user.repository';
import { JwtPayload } from '../../../shared/types/common.types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    @Inject(IUserRepository) private userRepository: IUserRepository, // FIX: Symbol
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET') || 'super-secret-key',
    });
  }

  async validate(payload: JwtPayload) {
    const user = await this.userRepository.findById(payload.sub);
    if (!user || !user.isActive) return null;
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      roles: payload.roles || [],
    };
  }
}
