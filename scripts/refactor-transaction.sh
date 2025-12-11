#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🚀 REFACTORING TRANSACTION MANAGEMENT (PURE CLEAN ARCHITECTURE)..."

# ============================================
# 1. UPDATE CORE PORTS (DEFINITIONS)
# ============================================
log "1. Updating Transaction Interfaces..."

# Định nghĩa Transaction là 'unknown' ở tầng Domain để không dính TypeORM
cat > src/core/shared/application/ports/transaction-manager.port.ts << 'EOF'
export type Transaction = unknown; // Opaque type

export interface ITransactionManager {
  runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T>;
}
EOF

# Cập nhật IRepository để nhận tham số tx (Optional)
cat > src/core/shared/application/ports/repository.port.ts << 'EOF'
import { Transaction } from './transaction-manager.port';

export interface IRepository<T, ID> {
  findById(id: ID, tx?: Transaction): Promise<T | null>;
  findAll(criteria?: Partial<T>, tx?: Transaction): Promise<T[]>;
  save(entity: T, tx?: Transaction): Promise<void>; // Hàm save nhận transaction
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
# 2. UPDATE INFRASTRUCTURE (ADAPTERS)
# ============================================
log "2. Updating Infrastructure Adapters..."

# Transaction Manager Implementation (Nơi duy nhất biết TypeORM)
cat > src/core/shared/infrastructure/persistence/typeorm-transaction.manager.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { DataSource, EntityManager } from 'typeorm';
import { ITransactionManager, Transaction } from '../../application/ports/transaction-manager.port';

@Injectable()
export class TypeOrmTransactionManager implements ITransactionManager {
  constructor(private dataSource: DataSource) {}

  async runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
    return this.dataSource.transaction(async (entityManager: EntityManager) => {
      // Ép kiểu EntityManager thành Transaction (unknown) để truyền xuống dưới
      return work(entityManager as unknown as Transaction);
    });
  }
}
EOF

# Abstract Repository (Xử lý ma thuật chọn Repository)
cat > src/core/shared/infrastructure/persistence/abstract-typeorm.repository.ts << 'EOF'
import { Repository, DeepPartial, ObjectLiteral, FindOptionsWhere, EntityManager } from 'typeorm';
import { IRepository } from '../../application/ports/repository.port';
import { Transaction } from '../../application/ports/transaction-manager.port';

export abstract class AbstractTypeOrmRepository<T extends ObjectLiteral>
  implements IRepository<T, any>
{
  protected constructor(protected readonly repository: Repository<T>) {}

  // Helper để lấy Repository đúng (nếu có tx thì lấy từ tx, không thì lấy default)
  protected getRepository(tx?: Transaction): Repository<T> {
    if (tx) {
      const entityManager = tx as EntityManager;
      return entityManager.getRepository(this.repository.target);
    }
    return this.repository;
  }

  async findById(id: any, tx?: Transaction): Promise<T | null> {
    const repo = this.getRepository(tx);
    const options = { where: { id } as unknown as FindOptionsWhere<T> };
    return repo.findOne(options);
  }

  async findAll(criteria?: Partial<T>, tx?: Transaction): Promise<T[]> {
    const repo = this.getRepository(tx);
    if (criteria) {
      return repo.find({ where: criteria as FindOptionsWhere<T> });
    }
    return repo.find();
  }

  async save(entity: T, tx?: Transaction): Promise<void> {
    const repo = this.getRepository(tx);
    await repo.save(entity as DeepPartial<T>);
  }

  async delete(id: any, tx?: Transaction): Promise<void> {
    const repo = this.getRepository(tx);
    await repo.delete(id);
  }

  async exists(id: any, tx?: Transaction): Promise<boolean> {
    const entity = await this.findById(id, tx);
    return !!entity;
  }
}
EOF

# ============================================
# 3. UPDATE MODULE REPOSITORIES (IMPLEMENTATION)
# ============================================
log "3. Updating Module Repositories..."

# User Repository Interface
cat > src/modules/user/domain/repositories/user-repository.interface.ts << 'EOF'
import { IRepository } from '../../../../core/shared/application/ports/repository.port';
import { User } from '../entities/user.entity';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

export interface IUserRepository extends IRepository<User, number> {
  findByUsername(username: string, tx?: Transaction): Promise<User | null>;
  findByEmail(email: string, tx?: Transaction): Promise<User | null>;
  // Overwrite save to return User (Abstract return void, but we need ID back)
  save(user: User, tx?: Transaction): Promise<User>;
}
EOF

# User Repository Implementation
cat > src/modules/user/infrastructure/persistence/typeorm-user.repository.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { AbstractTypeOrmRepository } from '../../../../core/shared/infrastructure/persistence/abstract-typeorm.repository';
import { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { User } from '../../domain/entities/user.entity';
import { UserOrmEntity } from './entities/user.orm-entity';
import { UserMapper } from './mappers/user.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class TypeOrmUserRepository
  extends AbstractTypeOrmRepository<UserOrmEntity>
  implements IUserRepository
{
  constructor(
    @InjectRepository(UserOrmEntity)
    repository: Repository<UserOrmEntity>,
  ) {
    super(repository);
  }

  // Override to map Domain <-> ORM

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

  // Override save to return Domain User with ID
  async save(user: User, tx?: Transaction): Promise<User> {
    const repo = this.getRepository(tx);
    const ormEntity = UserMapper.toPersistence(user);
    const saved = await repo.save(ormEntity);
    return UserMapper.toDomain(saved)!;
  }
}
EOF

# Session Repository Interface
cat > src/modules/auth/domain/repositories/session-repository.interface.ts << 'EOF'
import { Session } from '../entities/session.entity';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

export interface ISessionRepository {
  create(session: Session, tx?: Transaction): Promise<void>;
  findByUserId(userId: number): Promise<Session[]>;
  deleteByUserId(userId: number): Promise<void>;
}
EOF

# Session Repository Implementation
cat > src/modules/auth/infrastructure/persistence/typeorm-session.repository.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { ISessionRepository } from '../../domain/repositories/session-repository.interface';
import { Session } from '../../domain/entities/session.entity';
import { SessionOrmEntity } from './entities/session.orm-entity';
import { SessionMapper } from './mappers/session.mapper';
import { AbstractTypeOrmRepository } from '../../../../core/shared/infrastructure/persistence/abstract-typeorm.repository';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class TypeOrmSessionRepository
  extends AbstractTypeOrmRepository<SessionOrmEntity>
  implements ISessionRepository
{
  constructor(@InjectRepository(SessionOrmEntity) repo: Repository<SessionOrmEntity>) {
    super(repo);
  }

  async create(session: Session, tx?: Transaction): Promise<void> {
    const repo = this.getRepository(tx);
    const orm = SessionMapper.toPersistence(session);
    await repo.save(orm);
  }

  async findByUserId(userId: number): Promise<Session[]> {
    const orms = await this.repository.find({ where: { userId } });
    return orms.map(SessionMapper.toDomain).filter((s): s is Session => s !== null);
  }

  async deleteByUserId(userId: number): Promise<void> {
    await this.repository.delete({ userId });
  }
}
EOF

# ============================================
# 4. UPDATE AUTH SERVICE (THE FINAL PIECE)
# ============================================
log "4. Refactoring Authentication Service (Pure Clean Arch)..."

cat > src/modules/auth/application/services/authentication.service.ts << 'EOF'
import { Injectable, Inject, UnauthorizedException, BadRequestException, InternalServerErrorException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import type { ISessionRepository } from '../../domain/repositories/session-repository.interface';
import { PasswordUtil } from '../../../shared/utils/password.util';
import { User } from '../../../user/domain/entities/user.entity';
import { Session } from '../../domain/entities/session.entity';
import { JwtPayload } from '../../../shared/types/common.types';
import { ITransactionManager } from '../../../../core/shared/application/ports/transaction-manager.port'; // Import Port

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject('IUserRepository') private userRepository: IUserRepository,
    @Inject('ISessionRepository') private sessionRepository: ISessionRepository,
    @Inject('ITransactionManager') private txManager: ITransactionManager, // Inject Interface
    private jwtService: JwtService,
  ) {}

  // ... Login logic (giữ nguyên, chỉ cần update nếu muốn transaction cho login)
  async login(credentials: { username: string; password: string; ip?: string; userAgent?: string }): Promise<any> {
    const user = await this.userRepository.findByUsername(credentials.username);
    if (!user || !user.isActive) throw new UnauthorizedException('Invalid credentials');
    if (!user.hashedPassword) throw new UnauthorizedException('Password not set');
    if (!(await PasswordUtil.compare(credentials.password, user.hashedPassword))) {
        throw new UnauthorizedException('Invalid credentials');
    }
    return this.createTokenAndSession(user, credentials.ip, credentials.userAgent);
  }

  async register(data: any) {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) throw new BadRequestException('User exists');

    const hashedPassword = await PasswordUtil.hash(data.password);

    // Domain User
    const newUser = new User(
      undefined, data.username, data.email, hashedPassword, data.fullName,
      true, undefined, undefined, undefined, new Date(), new Date()
    );

    // CLEAN ARCHITECTURE TRANSACTION !!!
    return this.txManager.runInTransaction(async (tx) => {
        // 1. Save User with Transaction Context (tx)
        // Repo tự biết ép kiểu tx thành EntityManager bên trong
        const savedUser = await this.userRepository.save(newUser, tx);

        if (!savedUser.id) throw new InternalServerErrorException('User ID missing');

        // 2. Create Token
        const payload: JwtPayload = { sub: savedUser.id, username: savedUser.username, roles: [] };
        const accessToken = this.jwtService.sign(payload);

        // 3. Save Session with Transaction Context (tx)
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 1);

        const session = new Session(
            undefined, savedUser.id, accessToken, expiresAt, undefined, undefined, new Date()
        );

        await this.sessionRepository.create(session, tx);

        return { accessToken, user: savedUser.toJSON() };
    });
  }

  private async createTokenAndSession(user: User, ip?: string, userAgent?: string) {
    if (!user.id) throw new InternalServerErrorException();
    const payload: JwtPayload = { sub: user.id, username: user.username, roles: [] };
    const accessToken = this.jwtService.sign(payload);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 1);
    const session = new Session(undefined, user.id, accessToken, expiresAt, ip, userAgent, new Date());

    await this.sessionRepository.create(session); // Login thường ko cần transaction gắt gao
    return { accessToken, user: user.toJSON() };
  }

  async validateUser(payload: JwtPayload) {
    const user = await this.userRepository.findById(payload.sub);
    return (user && user.isActive) ? user.toJSON() : null;
  }
}
EOF

# ============================================
# 5. REGISTER TRANSACTION MANAGER IN SHARED MODULE
# ============================================
log "5. Registering TransactionManager Provider..."

cat > src/modules/shared/shared.module.ts << 'EOF'
import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmTransactionManager } from '../../core/shared/infrastructure/persistence/typeorm-transaction.manager';

@Global()
@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' })],
  providers: [
    {
      provide: 'ITransactionManager',
      useClass: TypeOrmTransactionManager,
    },
  ],
  exports: [ConfigModule, 'ITransactionManager'],
})
export class SharedModule {}
EOF

success "✅ TRANSACTION REFACTORING COMPLETE!"
echo "Service Layer now depends ONLY on Interfaces (Ports)."
echo "Infrastructure Layer handles the dirty TypeORM EntityManager casting."
echo "👉 Restart server: docker-compose restart api"
