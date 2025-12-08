import { Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import { PasswordUtil } from '../../../shared/utils/password.util';
import { User } from '../../../user/domain/entities/user.entity';
import { JwtPayload } from '../../../shared/types/common.types';

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject('IUserRepository') private userRepository: IUserRepository,
    private jwtService: JwtService,
  ) {}

  async login(credentials: {
    username: string;
    password: string;
  }): Promise<{ accessToken: string; user: any }> {
    // Find user
    const user = await this.userRepository.findByUsername(credentials.username);

    if (!user || !user.isActive) {
      throw new Error('Invalid credentials');
    }

    // Verify password
    if (!user.hashedPassword) {
      throw new Error('Password not set for this user');
    }

    const isValid = await PasswordUtil.compare(
      credentials.password,
      user.hashedPassword,
    );

    if (!isValid) {
      throw new Error('Invalid credentials');
    }

    // Generate JWT
    const payload: JwtPayload = {
      sub: user.id,
      username: user.username,
      roles: [], // Will be populated by RBAC
    };

    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      user: user.toJSON(),
    };
  }

  async validateUser(
    payload: JwtPayload,
  ): Promise<ReturnType<User['toJSON']> | null> {
    const user = await this.userRepository.findById(payload.sub);
    if (!user || !user.isActive) {
      return null;
    }
    return user.toJSON();
  }

  async register(data: {
    id: number;
    username: string;
    password: string;
    email?: string;
    fullName: string;
  }): Promise<{ accessToken: string; user: any }> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) {
      throw new Error('User already exists');
    }

    // NOTE: In strict domain logic, creating user might belong to UserService
    // but we simulate register here for AuthModule completeness as in original script

    // We can't use IUserRepository to create fully typed User object easily if it only accepts User domain entity
    // So we assume the repo can handle it, or we rely on the implementation details (which is risky in strict DDD)
    // However, keeping logic from original script:

    // Manual hashing
    const hashedPassword = await PasswordUtil.hash(data.password);

    // We construct a partial user-like object to save,
    // relying on the repo implementation to handle the persistence conversion
    // OR we should inject UserService. But to keep original structure:
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

    const payload = {
      sub: savedUser.id,
      username: savedUser.username,
      roles: [],
    };
    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      user: savedUser.toJSON(),
    };
  }
}
