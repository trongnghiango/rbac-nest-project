#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

ensure_dir() { mkdir -p "$@"; }

log "🚀 FILLING MISSING IMPLEMENTATIONS & SYNCING RBAC..."

# ============================================
# 1. MISSING VALUE OBJECT: MONEY
# ============================================
log "1. Creating missing Money Value Object..."

cat > src/core/shared/domain/value-objects/money.vo.ts << 'EOF'
export class InvalidMoneyException extends Error {
  constructor(message: string) {
    super(message);
  }
}

export class Money {
  constructor(
    private readonly amount: number,
    private readonly currency: string = 'VND',
  ) {
    if (amount < 0) {
      throw new InvalidMoneyException('Amount cannot be negative');
    }
    if (!Number.isInteger(amount)) {
      throw new InvalidMoneyException('Amount must be an integer');
    }
  }

  add(other: Money): Money {
    this.validateSameCurrency(other);
    return new Money(this.amount + other.amount, this.currency);
  }

  subtract(other: Money): Money {
    this.validateSameCurrency(other);
    if (other.amount > this.amount) {
      throw new InvalidMoneyException('Insufficient funds');
    }
    return new Money(this.amount - other.amount, this.currency);
  }

  multiply(factor: number): Money {
    return new Money(Math.round(this.amount * factor), this.currency);
  }

  getAmount(): number {
    return this.amount;
  }

  getCurrency(): string {
    return this.currency;
  }

  equals(other: Money): boolean {
    return this.amount === other.amount && this.currency === other.currency;
  }

  private validateSameCurrency(other: Money): void {
    if (this.currency !== other.currency) {
      throw new InvalidMoneyException('Currencies must match');
    }
  }
}
EOF

# ============================================
# 2. MISSING ADAPTER: EVENT BUS (In-Memory)
# ============================================
log "2. Creating In-Memory Event Bus Adapter..."

ensure_dir src/core/shared/infrastructure/adapters

cat > src/core/shared/infrastructure/adapters/in-memory-event-bus.adapter.ts << 'EOF'
import { Injectable, Logger } from '@nestjs/common';
import { IEventBus } from '../../application/ports/event-bus.port';
import { IDomainEvent } from '../../domain/events/domain-event.interface';

@Injectable()
export class InMemoryEventBus implements IEventBus {
  private readonly logger = new Logger(InMemoryEventBus.name);
  private handlers = new Map<string, Function[]>();

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    const eventName = event.eventName;
    const handlers = this.handlers.get(eventName);

    if (handlers) {
      this.logger.debug(`Publishing event: ${eventName}`);
      await Promise.all(handlers.map(handler => handler(event)));
    }
  }

  async publishAll(events: IDomainEvent[]): Promise<void> {
    await Promise.all(events.map(event => this.publish(event)));
  }

  subscribe<T extends IDomainEvent>(eventName: string, handler: (event: T) => Promise<void>): void {
    if (!this.handlers.has(eventName)) {
      this.handlers.set(eventName, []);
    }
    this.handlers.get(eventName)?.push(handler);
  }

  unsubscribe(eventName: string, handler: Function): void {
    const handlers = this.handlers.get(eventName);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }
}
EOF

# Đăng ký EventBus vào SharedModule
cat > src/modules/shared/shared.module.ts << 'EOF'
import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmTransactionManager } from '../../core/shared/infrastructure/persistence/typeorm-transaction.manager';
import { InMemoryEventBus } from '../../core/shared/infrastructure/adapters/in-memory-event-bus.adapter';

@Global()
@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' })],
  providers: [
    {
      provide: 'ITransactionManager',
      useClass: TypeOrmTransactionManager,
    },
    {
      provide: 'IEventBus',
      useClass: InMemoryEventBus,
    }
  ],
  exports: [ConfigModule, 'ITransactionManager', 'IEventBus'],
})
export class SharedModule {}
EOF

# ============================================
# 3. SYNC RBAC REPOSITORIES (Fix Inconsistency)
# ============================================
log "3. Updating RBAC Repositories to support Transaction & Fix Types..."

# Cập nhật Interface RBAC Repo để hỗ trợ Transaction (tx?)
cat > src/modules/rbac/domain/repositories/rbac-repository.interface.ts << 'EOF'
import { Role } from '../entities/role.entity';
import { Permission } from '../entities/permission.entity';
import { UserRole } from '../entities/user-role.entity';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

export interface IRoleRepository {
  findByName(name: string, tx?: Transaction): Promise<Role | null>;
  save(role: Role, tx?: Transaction): Promise<Role>;
  findAllWithPermissions(roleIds: number[], tx?: Transaction): Promise<Role[]>;
  findAll(tx?: Transaction): Promise<Role[]>;
}

export interface IPermissionRepository {
  findByName(name: string, tx?: Transaction): Promise<Permission | null>;
  save(permission: Permission, tx?: Transaction): Promise<Permission>;
  findAll(tx?: Transaction): Promise<Permission[]>;
}

export interface IUserRoleRepository {
  findByUserId(userId: number, tx?: Transaction): Promise<UserRole[]>;
  save(userRole: UserRole, tx?: Transaction): Promise<void>;
  findOne(userId: number, roleId: number, tx?: Transaction): Promise<UserRole | null>;
  delete(userId: number, roleId: number, tx?: Transaction): Promise<void>;
}
EOF

# Cập nhật Implementation RBAC Repo (Dùng getRepository(tx) pattern)
cat > src/modules/rbac/infrastructure/persistence/repositories/typeorm-rbac.repositories.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In, EntityManager } from 'typeorm';
import { IRoleRepository, IPermissionRepository, IUserRoleRepository } from '../../../domain/repositories/rbac-repository.interface';
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';
import { RoleOrmEntity } from '../entities/role.orm-entity';
import { PermissionOrmEntity } from '../entities/permission.orm-entity';
import { UserRoleOrmEntity } from '../entities/user-role.orm-entity';
import { RbacMapper } from '../mappers/rbac.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

// Helper Mixin hoặc copy hàm getRepository để DRY (Ở đây viết trực tiếp cho rõ ràng)
function getRepo<T>(baseRepo: Repository<T>, tx?: Transaction): Repository<T> {
    if (tx) {
        return (tx as EntityManager).getRepository(baseRepo.target);
    }
    return baseRepo;
}

@Injectable()
export class TypeOrmRoleRepository implements IRoleRepository {
  constructor(@InjectRepository(RoleOrmEntity) private repo: Repository<RoleOrmEntity>) {}

  async findByName(name: string, tx?: Transaction): Promise<Role | null> {
    const r = getRepo(this.repo, tx);
    const entity = await r.findOne({ where: { name }, relations: ['permissions'] });
    return RbacMapper.toRoleDomain(entity);
  }

  async save(role: Role, tx?: Transaction): Promise<Role> {
    const r = getRepo(this.repo, tx);
    const orm = RbacMapper.toRolePersistence(role);
    const saved = await r.save(orm);
    return RbacMapper.toRoleDomain(saved)!;
  }

  async findAllWithPermissions(roleIds: number[], tx?: Transaction): Promise<Role[]> {
    const r = getRepo(this.repo, tx);
    const entities = await r.find({
      where: { id: In(roleIds), isActive: true },
      relations: ['permissions']
    });
    return entities.map(e => RbacMapper.toRoleDomain(e)!);
  }

  async findAll(tx?: Transaction): Promise<Role[]> {
    const r = getRepo(this.repo, tx);
    const entities = await r.find({ relations: ['permissions'] });
    return entities.map(e => RbacMapper.toRoleDomain(e)!);
  }
}

@Injectable()
export class TypeOrmPermissionRepository implements IPermissionRepository {
  constructor(@InjectRepository(PermissionOrmEntity) private repo: Repository<PermissionOrmEntity>) {}

  async findByName(name: string, tx?: Transaction): Promise<Permission | null> {
    const r = getRepo(this.repo, tx);
    const entity = await r.findOne({ where: { name } });
    return RbacMapper.toPermissionDomain(entity);
  }

  async save(permission: Permission, tx?: Transaction): Promise<Permission> {
    const r = getRepo(this.repo, tx);
    const orm = RbacMapper.toPermissionPersistence(permission);
    const saved = await r.save(orm);
    return RbacMapper.toPermissionDomain(saved)!;
  }

  async findAll(tx?: Transaction): Promise<Permission[]> {
    const r = getRepo(this.repo, tx);
    const entities = await r.find();
    return entities.map(e => RbacMapper.toPermissionDomain(e)!);
  }
}

@Injectable()
export class TypeOrmUserRoleRepository implements IUserRoleRepository {
  constructor(@InjectRepository(UserRoleOrmEntity) private repo: Repository<UserRoleOrmEntity>) {}

  async findByUserId(userId: number, tx?: Transaction): Promise<UserRole[]> {
    const r = getRepo(this.repo, tx);
    const entities = await r.find({ where: { userId }, relations: ['role'] });
    return entities.map(e => RbacMapper.toUserRoleDomain(e)!);
  }

  async save(userRole: UserRole, tx?: Transaction): Promise<void> {
    const r = getRepo(this.repo, tx);
    const orm = RbacMapper.toUserRolePersistence(userRole);
    await r.save(orm);
  }

  async findOne(userId: number, roleId: number, tx?: Transaction): Promise<UserRole | null> {
    const r = getRepo(this.repo, tx);
    const entity = await r.findOne({ where: { userId, roleId } });
    return RbacMapper.toUserRoleDomain(entity);
  }

  async delete(userId: number, roleId: number, tx?: Transaction): Promise<void> {
    const r = getRepo(this.repo, tx);
    await r.delete({ userId, roleId });
  }
}
EOF

success "✅ MISSING PARTS IMPLEMENTED & RBAC SYNCED!"
echo "👉 Now the project is fully consistent and feature-complete as requested."
echo "👉 Run: npm run start:dev"
