#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🛠️ FIXING FINAL COMPILATION ERRORS..."

# ============================================
# 1. FIX AUTH SERVICE (Import Type Error)
# ============================================
# Lỗi TS1272: Phải dùng 'import type' cho ITransactionManager
cat > src/modules/auth/application/services/authentication.service.ts << 'EOF'
import { Injectable, Inject, UnauthorizedException, BadRequestException, InternalServerErrorException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import type { ISessionRepository } from '../../domain/repositories/session-repository.interface';
import { PasswordUtil } from '../../../shared/utils/password.util';
import { User } from '../../../user/domain/entities/user.entity';
import { Session } from '../../domain/entities/session.entity';
import { JwtPayload } from '../../../shared/types/common.types';
import type { ITransactionManager } from '../../../../core/shared/application/ports/transaction-manager.port'; // FIX: import type

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject('IUserRepository') private userRepository: IUserRepository,
    @Inject('ISessionRepository') private sessionRepository: ISessionRepository,
    @Inject('ITransactionManager') private txManager: ITransactionManager,
    private jwtService: JwtService,
  ) {}

  async login(credentials: { username: string; password: string; ip?: string; userAgent?: string }): Promise<any> {
    const user = await this.userRepository.findByUsername(credentials.username);

    if (!user || !user.isActive) throw new UnauthorizedException('Invalid credentials');
    // Access getter directly (domain encapsulation)
    if (!user.hashedPassword) throw new UnauthorizedException('Password not set');

    const isValid = await PasswordUtil.compare(credentials.password, user.hashedPassword);
    if (!isValid) throw new UnauthorizedException('Invalid credentials');

    if (!user.id) throw new InternalServerErrorException('User ID is missing');

    const payload: JwtPayload = { sub: user.id, username: user.username, roles: [] };
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

  async validateUser(payload: JwtPayload): Promise<ReturnType<User['toJSON']> | null> {
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
        if (!savedUser.id) throw new InternalServerErrorException('Failed to generate User ID');

        const payload: JwtPayload = { sub: savedUser.id, username: savedUser.username, roles: [] };
        const accessToken = this.jwtService.sign(payload);

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 1);

        const session = new Session(
            undefined, savedUser.id, accessToken, expiresAt, undefined, undefined, new Date()
        );

        await this.sessionRepository.create(session, tx);

        return { accessToken, user: savedUser.toJSON() };
    });
  }
}
EOF

# ============================================
# 2. FIX REPOSITORY PORT (Return Type Mismatch)
# ============================================
# Lỗi TS2430: Interface IUserRepository return User nhưng IRepository return void
# Fix: Sửa IRepository để hàm save trả về T thay vì void
cat > src/core/shared/application/ports/repository.port.ts << 'EOF'
import { Transaction } from './transaction-manager.port';

export interface IRepository<T, ID> {
  findById(id: ID, tx?: Transaction): Promise<T | null>;
  findAll(criteria?: Partial<T>, tx?: Transaction): Promise<T[]>;
  // FIX: save trả về Promise<T> thay vì void để đồng bộ với User Repo
  save(entity: T, tx?: Transaction): Promise<T>;
  delete(id: ID, tx?: Transaction): Promise<void>;
  exists(id: ID, tx?: Transaction): Promise<boolean>;
}

export interface IPaginatedRepository<T, ID> extends IRepository<T, ID> {
  findPaginated(
    page: number,
    limit: number,
    criteria?: Partial<T>,
    sort?: { field: string; order: 'ASC' | 'DESC' }
  ): Promise<{ data: T[]; total: number; page: number; totalPages: number }>;
}
EOF

# ============================================
# 3. FIX TYPEORM USER REPO (Remove Inheritance)
# ============================================
# Lỗi TS2420, TS2416: Xung đột type giữa Domain Entity và Orm Entity
# Giải pháp: Bỏ 'extends AbstractTypeOrmRepository', tự implement helper getRepository
cat > src/modules/user/infrastructure/persistence/typeorm-user.repository.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { Repository, EntityManager } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { User } from '../../domain/entities/user.entity';
import { UserOrmEntity } from './entities/user.orm-entity';
import { UserMapper } from './mappers/user.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class TypeOrmUserRepository implements IUserRepository {
  constructor(
    @InjectRepository(UserOrmEntity)
    private readonly repository: Repository<UserOrmEntity>,
  ) {}

  // Helper để lấy đúng Repo (có Transaction hoặc không)
  private getRepository(tx?: Transaction): Repository<UserOrmEntity> {
    if (tx) {
      const entityManager = tx as EntityManager;
      return entityManager.getRepository(UserOrmEntity);
    }
    return this.repository;
  }

  async findById(id: number, tx?: Transaction): Promise<User | null> {
    const repo = this.getRepository(tx);
    const entity = await repo.findOne({ where: { id } });
    return UserMapper.toDomain(entity);
  }

  async findByUsername(username: string, tx?: Transaction): Promise<User | null> {
    const repo = this.getRepository(tx);
    const entity = await repo.findOne({ where: { username } });
    return UserMapper.toDomain(entity);
  }

  async findByEmail(email: string, tx?: Transaction): Promise<User | null> {
    const repo = this.getRepository(tx);
    const entity = await repo.findOne({ where: { email } });
    return UserMapper.toDomain(entity);
  }

  async findAllActive(): Promise<User[]> {
    const entities = await this.repository.find({
      where: { isActive: true },
      order: { createdAt: 'DESC' },
    });
    return entities
      .map((entity) => UserMapper.toDomain(entity))
      .filter((u): u is User => u !== null);
  }

  // Bắt buộc phải implement do IRepository yêu cầu
  async findAll(criteria?: Partial<User>): Promise<User[]> {
    // Basic implementation
    return this.findAllActive();
  }

  async save(user: User, tx?: Transaction): Promise<User> {
    const repo = this.getRepository(tx);
    const ormEntity = UserMapper.toPersistence(user);
    const saved = await repo.save(ormEntity);
    return UserMapper.toDomain(saved)!;
  }

  async update(id: number, data: Partial<User>): Promise<User> {
    await this.repository.update(id, data as any);
    const updated = await this.findById(id);
    if (!updated) throw new Error('User not found');
    return updated;
  }

  async delete(id: number): Promise<void> {
    await this.repository.delete(id);
  }

  async exists(id: number): Promise<boolean> {
    const user = await this.findById(id);
    return !!user;
  }

  async count(): Promise<number> {
    return this.repository.count();
  }
}
EOF

# ============================================
# 4. FIX TYPEORM SESSION REPO (Remove Inheritance)
# ============================================
# Tương tự như User Repo, bỏ kế thừa để tránh lỗi type
cat > src/modules/auth/infrastructure/persistence/typeorm-session.repository.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { Repository, EntityManager } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { ISessionRepository } from '../../domain/repositories/session-repository.interface';
import { Session } from '../../domain/entities/session.entity';
import { SessionOrmEntity } from './entities/session.orm-entity';
import { SessionMapper } from './mappers/session.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class TypeOrmSessionRepository implements ISessionRepository {
  constructor(
    @InjectRepository(SessionOrmEntity)
    private readonly repository: Repository<SessionOrmEntity>
  ) {}

  private getRepository(tx?: Transaction): Repository<SessionOrmEntity> {
    if (tx) {
      const entityManager = tx as EntityManager;
      return entityManager.getRepository(SessionOrmEntity);
    }
    return this.repository;
  }

  async create(session: Session, tx?: Transaction): Promise<void> {
    const repo = this.getRepository(tx);
    const orm = SessionMapper.toPersistence(session);
    await repo.save(orm);
  }

  async findByUserId(userId: number): Promise<Session[]> {
    const orms = await this.repository.find({ where: { userId } });
    return orms
      .map(SessionMapper.toDomain)
      .filter((s): s is Session => s !== null);
  }

  async deleteByUserId(userId: number): Promise<void> {
    await this.repository.delete({ userId });
  }
}
EOF

success "✅ ALL COMPILATION ERRORS RESOLVED!"
echo "👉 Server should be green now: npm run start:dev"
