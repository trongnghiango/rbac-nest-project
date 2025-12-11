import {
  Injectable,
  Inject,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import type { ISessionRepository } from '../../domain/repositories/session-repository.interface';
import { PasswordUtil } from '../../../shared/utils/password.util';
import { User } from '../../../user/domain/entities/user.entity';
import { Session } from '../../domain/entities/session.entity';
import { JwtPayload } from '../../../shared/types/common.types';
import type {
  ITransactionManager,
  Transaction,
} from '../../../../core/shared/application/ports/transaction-manager.port'; // FIX: import type

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject('IUserRepository') private userRepository: IUserRepository,
    @Inject('ISessionRepository') private sessionRepository: ISessionRepository,
    @Inject('ITransactionManager') private txManager: ITransactionManager,
    private jwtService: JwtService,
  ) {}

  private async createSessionForUser(
    user: User,
    ip?: string,
    agent?: string,
    tx?: Transaction,
  ) {
    const payload: JwtPayload = {
      sub: user.id!,
      username: user.username,
      roles: [], // Nên fetch role thật của user để nhét vào đây nếu cần claim-based
    };
    const accessToken = this.jwtService.sign(payload);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 1);

    const session = new Session(
      undefined,
      user.id!,
      accessToken,
      expiresAt,
      ip,
      agent,
      new Date(),
    );

    await this.sessionRepository.create(session, tx);

    return { accessToken, user: user.toJSON() };
  }

  async login(credentials: {
    username: string;
    password: string;
    ip?: string;
    userAgent?: string;
  }): Promise<any> {
    const user = await this.userRepository.findByUsername(credentials.username);

    if (!user || !user.isActive)
      throw new UnauthorizedException('Invalid credentials');
    // Access getter directly (domain encapsulation)
    if (!user.hashedPassword)
      throw new UnauthorizedException('Password not set');

    const isValid = await PasswordUtil.compare(
      credentials.password,
      user.hashedPassword,
    );
    if (!isValid) throw new UnauthorizedException('Invalid credentials');

    if (!user.id) throw new InternalServerErrorException('User ID is missing');

    return this.createSessionForUser(
      user,
      credentials.ip,
      credentials.userAgent,
    );
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
      return this.createSessionForUser(savedUser, undefined, undefined, tx);
    });

    // return this.txManager.runInTransaction(async (tx) => {
    //   const savedUser = await this.userRepository.save(newUser, tx);
    //   if (!savedUser.id)
    //     throw new InternalServerErrorException('Failed to generate User ID');
    //
    //   const payload: JwtPayload = {
    //     sub: savedUser.id,
    //     username: savedUser.username,
    //     roles: [],
    //   };
    //   const accessToken = this.jwtService.sign(payload);
    //
    //   const expiresAt = new Date();
    //   expiresAt.setDate(expiresAt.getDate() + 1);
    //
    //   const session = new Session(
    //     undefined,
    //     savedUser.id,
    //     accessToken,
    //     expiresAt,
    //     undefined,
    //     undefined,
    //     new Date(),
    //   );
    //
    //   await this.sessionRepository.create(session, tx);
    //
    //   return { accessToken, user: savedUser.toJSON() };
    // });
  }
}
