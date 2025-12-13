import {
  Injectable,
  Inject,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { IUserRepository } from '@modules/user/domain/repositories/user.repository';
import { ISessionRepository } from '../../domain/repositories/session.repository';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { PasswordUtil } from '@core/shared/utils/password.util';
import { User } from '@modules/user/domain/entities/user.entity';
import { Session } from '../../domain/entities/session.entity';
import { JwtPayload } from '@core/shared/types/common.types';

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject(IUserRepository) private userRepository: IUserRepository,
    @Inject(ISessionRepository) private sessionRepository: ISessionRepository,
    @Inject(ITransactionManager) private txManager: ITransactionManager,
    private jwtService: JwtService,
  ) {}

  async login(credentials: {
    username: string;
    password: string;
    ip?: string;
    userAgent?: string;
  }): Promise<any> {
    const user = await this.userRepository.findByUsername(credentials.username);

    if (!user || !user.isActive)
      throw new UnauthorizedException('Invalid credentials');
    if (!user.hashedPassword)
      throw new UnauthorizedException('Password not set');

    const isValid = await PasswordUtil.compare(
      credentials.password,
      user.hashedPassword,
    );
    if (!isValid) throw new UnauthorizedException('Invalid credentials');

    if (!user.id) throw new InternalServerErrorException('User ID is missing');

    const payload: JwtPayload = {
      sub: user.id,
      username: user.username,
      roles: [],
    };
    const accessToken = this.jwtService.sign(payload);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 1);

    const session = new Session(
      undefined,
      user.id,
      accessToken,
      expiresAt,
      credentials.ip,
      credentials.userAgent,
      new Date(),
    );

    await this.sessionRepository.create(session);

    return {
      accessToken,
      user: user.toJSON(),
    };
  }

  async validateUser(
    payload: JwtPayload,
  ): Promise<ReturnType<User['toJSON']> | null> {
    const user = await this.userRepository.findById(payload.sub);
    if (!user || !user.isActive) return null;
    return user.toJSON();
  }

  async register(data: any): Promise<any> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) throw new BadRequestException('User already exists');

    const hashedPassword = await PasswordUtil.hash(data.password);

    const newUser = new User(
      undefined,
      data.username,
      data.email,
      hashedPassword,
      data.fullName,
      true,
      undefined,
      undefined,
      undefined,
      new Date(),
      new Date(),
    );

    return this.txManager.runInTransaction(async (tx) => {
      const savedUser = await this.userRepository.save(newUser, tx);
      if (!savedUser.id)
        throw new InternalServerErrorException('Failed to generate User ID');

      const payload: JwtPayload = {
        sub: savedUser.id,
        username: savedUser.username,
        roles: [],
      };
      const accessToken = this.jwtService.sign(payload);

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 1);

      const session = new Session(
        undefined,
        savedUser.id,
        accessToken,
        expiresAt,
        undefined,
        undefined,
        new Date(),
      );

      await this.sessionRepository.create(session, tx);

      return { accessToken, user: savedUser.toJSON() };
    });
  }
}
