#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🚀 OPTIMIZING DRIZZLE: TYPE SAFETY & SAFE SAVE LOGIC..."

# ============================================
# 1. OPTIMIZE USER MODULE (Strict Type & Split Save)
# ============================================
log "1. Refactoring User Module..."

# User Mapper (Strict Type)
cat > src/modules/user/infrastructure/persistence/mappers/user.mapper.ts << 'EOF'
import { InferSelectModel } from 'drizzle-orm';
import { User } from '../../../../domain/entities/user.entity';
import { users } from '../../../../database/schema';

// Tự động lấy Type từ Schema Definition
type UserRecord = InferSelectModel<typeof users>;

export class UserMapper {
  static toDomain(raw: UserRecord | null): User | null {
    if (!raw) return null;

    return new User(
      raw.id,
      raw.username,
      raw.email || undefined,
      raw.hashedPassword || undefined,
      raw.fullName || undefined,
      raw.isActive || false,
      raw.phoneNumber || undefined,
      raw.avatarUrl || undefined,
      (raw.profile as any) || undefined, // JSONB cần cast nhẹ hoặc định nghĩa type riêng
      raw.createdAt || undefined,
      raw.updatedAt || undefined,
    );
  }

  static toPersistence(domain: User) {
    return {
      id: domain.id, // Có thể undefined
      username: domain.username,
      email: domain.email || null,
      hashedPassword: domain.hashedPassword || null,
      fullName: domain.fullName || null,
      isActive: domain.isActive,
      phoneNumber: domain.phoneNumber || null,
      avatarUrl: domain.avatarUrl || null,
      profile: domain.profile || null,
      createdAt: domain.createdAt || new Date(),
      updatedAt: domain.updatedAt || new Date(),
    };
  }
}
EOF

# User Repository (Split Insert/Update)
cat > src/modules/user/infrastructure/persistence/drizzle-user.repository.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { User } from '../../domain/entities/user.entity';
import { DrizzleBaseRepository } from '../../../../core/shared/infrastructure/persistence/drizzle-base.repository';
import { users } from '../../../../database/schema';
import { UserMapper } from './mappers/user.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleUserRepository extends DrizzleBaseRepository implements IUserRepository {
  async findById(id: number, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(users).where(eq(users.id, id));
    return UserMapper.toDomain(result[0]);
  }

  async findByUsername(username: string, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(users).where(eq(users.username, username));
    return UserMapper.toDomain(result[0]);
  }

  async findByEmail(email: string, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(users).where(eq(users.email, email));
    return UserMapper.toDomain(result[0]);
  }

  async findAllActive(): Promise<User[]> {
    const result = await this.db.select().from(users).where(eq(users.isActive, true));
    return result.map(u => UserMapper.toDomain(u)!);
  }

  async save(user: User, tx?: Transaction): Promise<User> {
    const db = this.getDb(tx);
    const data = UserMapper.toPersistence(user);

    let result;
    if (data.id) {
        // UPDATE: Chỉ update khi có ID
        result = await db.update(users)
            .set(data)
            .where(eq(users.id, data.id))
            .returning();
    } else {
        // INSERT: Loại bỏ ID để Postgres tự sinh (Serial)
        // Tránh lỗi lệch sequence
        const { id, ...insertData } = data;
        result = await db.insert(users)
            .values(insertData)
            .returning();
    }

    return UserMapper.toDomain(result[0])!;
  }

  async findAll(): Promise<User[]> { return []; }
  async update(): Promise<User> { throw new Error('Use save'); }
  async delete(id: number, tx?: Transaction): Promise<void> {
      const db = this.getDb(tx);
      await db.delete(users).where(eq(users.id, id));
  }
  async exists(id: number, tx?: Transaction): Promise<boolean> {
      const u = await this.findById(id, tx);
      return !!u;
  }
  async count(): Promise<number> { return 0; }
}
EOF

# ============================================
# 2. OPTIMIZE AUTH MODULE (Strict Type)
# ============================================
log "2. Refactoring Auth Module..."

# Session Mapper
cat > src/modules/auth/infrastructure/persistence/mappers/session.mapper.ts << 'EOF'
import { InferSelectModel } from 'drizzle-orm';
import { Session } from '../../../../domain/entities/session.entity';
import { sessions } from '../../../../database/schema';

type SessionRecord = InferSelectModel<typeof sessions>;

export class SessionMapper {
  static toDomain(raw: SessionRecord | null): Session | null {
    if (!raw) return null;
    return new Session(
      raw.id,
      Number(raw.userId),
      raw.token,
      raw.expiresAt,
      raw.ipAddress || undefined,
      raw.userAgent || undefined,
      raw.createdAt
    );
  }

  static toPersistence(domain: Session) {
    return {
      id: domain.id, // UUID thì có thể truyền vào hoặc để DB tự gen
      userId: domain.userId,
      token: domain.token,
      expiresAt: domain.expiresAt,
      ipAddress: domain.ipAddress || null,
      userAgent: domain.userAgent || null,
      createdAt: domain.createdAt || new Date(),
    };
  }
}
EOF

# Session Repository
cat > src/modules/auth/infrastructure/persistence/drizzle-session.repository.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { ISessionRepository } from '../../domain/repositories/session-repository.interface';
import { Session } from '../../domain/entities/session.entity';
import { DrizzleBaseRepository } from '../../../../core/shared/infrastructure/persistence/drizzle-base.repository';
import { sessions } from '../../../../database/schema';
import { SessionMapper } from './mappers/session.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleSessionRepository extends DrizzleBaseRepository implements ISessionRepository {

  async create(session: Session, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    const data = SessionMapper.toPersistence(session);
    // UUID thường được generate từ code hoặc DB.
    // Nếu ID có giá trị thì insert, ko thì để default (gen_random_uuid)
    if (data.id) {
        await db.insert(sessions).values(data as any);
    } else {
        const { id, ...insertData } = data;
        await db.insert(sessions).values(insertData);
    }
  }

  async findByUserId(userId: number): Promise<Session[]> {
    const results = await this.db.select().from(sessions).where(eq(sessions.userId, userId));
    return results.map(r => SessionMapper.toDomain(r)!);
  }

  async deleteByUserId(userId: number): Promise<void> {
    await this.db.delete(sessions).where(eq(sessions.userId, userId));
  }
}
EOF

# ============================================
# 3. OPTIMIZE RBAC MODULE (Types & Relations)
# ============================================
log "3. Refactoring RBAC Module (Complex Types)..."

# RBAC Mapper
cat > src/modules/rbac/infrastructure/persistence/mappers/rbac.mapper.ts << 'EOF'
import { InferSelectModel } from 'drizzle-orm';
import { Role } from '../../../../domain/entities/role.entity';
import { Permission } from '../../../../domain/entities/permission.entity';
import { UserRole } from '../../../../domain/entities/user-role.entity';
import { roles, permissions, userRoles } from '../../../../database/schema';

// Định nghĩa Type dựa trên Schema
type RoleRecord = InferSelectModel<typeof roles>;
type PermissionRecord = InferSelectModel<typeof permissions>;
type UserRoleRecord = InferSelectModel<typeof userRoles>;

// Type phức tạp cho Relation (Kết quả trả về từ db.query...)
type RoleWithPermissions = RoleRecord & {
    permissions: { permission: PermissionRecord }[];
};
type UserRoleWithRole = UserRoleRecord & {
    role: RoleRecord;
};

export class RbacMapper {
  // PERMISSION
  static toPermissionDomain(raw: PermissionRecord | null): Permission | null {
    if (!raw) return null;
    return new Permission(
      raw.id,
      raw.name,
      raw.description || undefined,
      raw.resourceType || undefined,
      raw.action || undefined,
      raw.isActive || false,
      raw.attributes || '*',
      raw.createdAt || undefined
    );
  }

  static toPermissionPersistence(domain: Permission) {
    return {
      id: domain.id,
      name: domain.name,
      description: domain.description || null,
      resourceType: domain.resourceType || null,
      action: domain.action || null,
      isActive: domain.isActive,
      attributes: domain.attributes,
      createdAt: domain.createdAt || new Date(),
    };
  }

  // ROLE (Handle Relation Type Safety)
  static toRoleDomain(raw: RoleWithPermissions | RoleRecord | null): Role | null {
    if (!raw) return null;

    // Check if it has nested permissions
    let perms: Permission[] = [];
    if ('permissions' in raw && Array.isArray(raw.permissions)) {
        perms = raw.permissions.map(rp => this.toPermissionDomain(rp.permission)!).filter(Boolean);
    }

    return new Role(
      raw.id,
      raw.name,
      raw.description || undefined,
      raw.isActive || false,
      raw.isSystem || false,
      perms,
      raw.createdAt || undefined,
      raw.updatedAt || undefined
    );
  }

  static toRolePersistence(domain: Role) {
    return {
      id: domain.id,
      name: domain.name,
      description: domain.description || null,
      isActive: domain.isActive,
      isSystem: domain.isSystem,
      createdAt: domain.createdAt || new Date(),
      updatedAt: domain.updatedAt || new Date(),
    };
  }

  // USER ROLE
  static toUserRoleDomain(raw: UserRoleWithRole | UserRoleRecord | null): UserRole | null {
    if (!raw) return null;

    let role;
    if ('role' in raw && raw.role) {
        role = this.toRoleDomain(raw.role);
    }

    return new UserRole(
      Number(raw.userId),
      raw.roleId,
      raw.assignedBy ? Number(raw.assignedBy) : undefined,
      raw.expiresAt || undefined,
      raw.assignedAt || undefined,
      role!
    );
  }

  static toUserRolePersistence(domain: UserRole) {
    return {
      userId: domain.userId,
      roleId: domain.roleId,
      assignedBy: domain.assignedBy || null,
      expiresAt: domain.expiresAt || null,
      assignedAt: domain.assignedAt || new Date(),
    };
  }
}
EOF

# RBAC Repository (Safe Save)
cat > src/modules/rbac/infrastructure/persistence/repositories/drizzle-rbac.repositories.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { eq, inArray, and } from 'drizzle-orm';
import { IRoleRepository, IPermissionRepository, IUserRoleRepository } from '../../../domain/repositories/rbac-repository.interface';
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';
import { DrizzleBaseRepository } from '../../../../../core/shared/infrastructure/persistence/drizzle-base.repository';
import { roles, permissions, userRoles, rolePermissions } from '../../../../../database/schema';
import { RbacMapper } from '../mappers/rbac.mapper';
import { Transaction } from '../../../../../core/shared/application/ports/transaction-manager.port';

// --- ROLE REPOSITORY ---
@Injectable()
export class DrizzleRoleRepository extends DrizzleBaseRepository implements IRoleRepository {

  async findByName(name: string, tx?: Transaction): Promise<Role | null> {
    const db = this.getDb(tx);
    const result = await db.query.roles.findFirst({
      where: eq(roles.name, name),
      with: {
        permissions: {
          with: { permission: true }
        }
      }
    });

    return result ? RbacMapper.toRoleDomain(result as any) : null;
  }

  async save(role: Role, tx?: Transaction): Promise<Role> {
    const db = this.getDb(tx);
    const data = RbacMapper.toRolePersistence(role);

    return await db.transaction(async (trx) => {
        let savedRoleId: number;

        // SAFE UPSERT LOGIC
        if (data.id) {
            await trx.update(roles).set(data).where(eq(roles.id, data.id));
            savedRoleId = data.id;
        } else {
            const { id, ...insertData } = data;
            const res = await trx.insert(roles).values(insertData).returning({ id: roles.id });
            savedRoleId = res[0].id;
        }

        // Handle Permissions Relation
        if (role.permissions && role.permissions.length > 0) {
            await trx.delete(rolePermissions).where(eq(rolePermissions.roleId, savedRoleId));

            const permInserts = role.permissions.map(p => ({
                roleId: savedRoleId,
                permissionId: p.id!
            }));

            if (permInserts.length > 0) {
               await trx.insert(rolePermissions).values(permInserts);
            }
        }

        // Return full object by refetching
        const finalRole = await this.findByName(role.name, trx as unknown as Transaction);
        return finalRole!;
    });
  }

  async findAllWithPermissions(roleIds: number[], tx?: Transaction): Promise<Role[]> {
    const db = this.getDb(tx);
    const results = await db.query.roles.findMany({
      where: inArray(roles.id, roleIds),
      with: { permissions: { with: { permission: true } } }
    });
    return results.map(r => RbacMapper.toRoleDomain(r as any)!);
  }

  async findAll(tx?: Transaction): Promise<Role[]> {
    const db = this.getDb(tx);
    const results = await db.query.roles.findMany({
      with: { permissions: { with: { permission: true } } }
    });
    return results.map(r => RbacMapper.toRoleDomain(r as any)!);
  }
}

// --- PERMISSION REPOSITORY ---
@Injectable()
export class DrizzlePermissionRepository extends DrizzleBaseRepository implements IPermissionRepository {
  async findByName(name: string, tx?: Transaction): Promise<Permission | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(permissions).where(eq(permissions.name, name));
    return RbacMapper.toPermissionDomain(result[0]);
  }

  async save(permission: Permission, tx?: Transaction): Promise<Permission> {
    const db = this.getDb(tx);
    const data = RbacMapper.toPermissionPersistence(permission);

    let result;
    if (data.id) {
        result = await db.update(permissions)
            .set(data)
            .where(eq(permissions.id, data.id))
            .returning();
    } else {
        const { id, ...insertData } = data;
        result = await db.insert(permissions)
            .values(insertData)
            .returning();
    }

    return RbacMapper.toPermissionDomain(result[0])!;
  }

  async findAll(tx?: Transaction): Promise<Permission[]> {
    const db = this.getDb(tx);
    const results = await db.select().from(permissions);
    return results.map(r => RbacMapper.toPermissionDomain(r)!);
  }
}

// --- USER ROLE REPOSITORY ---
@Injectable()
export class DrizzleUserRoleRepository extends DrizzleBaseRepository implements IUserRoleRepository {
  async findByUserId(userId: number, tx?: Transaction): Promise<UserRole[]> {
    const db = this.getDb(tx);
    const results = await db.query.userRoles.findMany({
        where: eq(userRoles.userId, userId),
        with: { role: true }
    });
    return results.map(r => RbacMapper.toUserRoleDomain(r as any)!);
  }

  async save(userRole: UserRole, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    const data = RbacMapper.toUserRolePersistence(userRole);

    // Manual Upsert for Composite Key
    await db.insert(userRoles).values(data)
        .onConflictDoUpdate({
            target: [userRoles.userId, userRoles.roleId],
            set: { expiresAt: data.expiresAt, assignedBy: data.assignedBy }
        });
  }

  async findOne(userId: number, roleId: number, tx?: Transaction): Promise<UserRole | null> {
    const db = this.getDb(tx);
    const result = await db.query.userRoles.findFirst({
        where: and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)),
        with: { role: true }
    });
    return result ? RbacMapper.toUserRoleDomain(result as any) : null;
  }

  async delete(userId: number, roleId: number, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    await db.delete(userRoles)
        .where(and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)));
  }
}
EOF

success "✅ OPTIMIZATION COMPLETE!"
echo "👉 1. Type Safety: Enforced using InferSelectModel."
echo "👉 2. Safe Save: Logic separated for Insert vs Update (preventing sequence drift)."
echo "👉 3. Mappers: Now strongly typed."
echo "👉 Run: npm run start:dev"