#!/bin/bash

# ============================================
# COMPLETE FIX FOR RBAC MAPPER
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🛠️ WRITING FULL RBAC MAPPER..."

cat > src/modules/rbac/infrastructure/persistence/mappers/rbac.mapper.ts << 'EOF'
import { InferSelectModel, InferInsertModel } from 'drizzle-orm';

// FIX: 3 cấp ../ để về thư mục 'rbac'
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';

// FIX: 5 cấp ../ để về thư mục 'src' -> 'database'
import { roles, permissions, userRoles } from '../../../../../database/schema';

type RoleSelect = InferSelectModel<typeof roles>;
type PermissionSelect = InferSelectModel<typeof permissions>;
type UserRoleSelect = InferSelectModel<typeof userRoles>;

type RoleWithRelations = RoleSelect & {
    permissions: { permission: PermissionSelect }[];
};

type UserRoleWithRole = UserRoleSelect & {
    role: RoleSelect;
};

export class RbacMapper {
  static toPermissionDomain(raw: PermissionSelect | null): Permission | null {
    if (!raw) return null;
    return new Permission(
      raw.id,
      raw.name,
      raw.description || undefined,
      raw.resourceType || undefined,
      raw.action || undefined,
      raw.isActive ?? true,
      raw.attributes || '*',
      raw.createdAt || undefined
    );
  }

  static toPermissionPersistence(domain: Permission): InferInsertModel<typeof permissions> {
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

  static toRoleDomain(raw: RoleWithRelations | RoleSelect | null): Role | null {
    if (!raw) return null;

    let perms: Permission[] = [];
    // Kiểm tra an toàn xem có permissions được join vào không
    if ('permissions' in raw && Array.isArray(raw.permissions)) {
        perms = raw.permissions.map(rp => this.toPermissionDomain(rp.permission)!).filter(Boolean);
    }

    return new Role(
      raw.id,
      raw.name,
      raw.description || undefined,
      raw.isActive ?? true,
      raw.isSystem ?? false,
      perms,
      raw.createdAt || undefined,
      raw.updatedAt || undefined
    );
  }

  static toRolePersistence(domain: Role): InferInsertModel<typeof roles> {
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

  static toUserRoleDomain(raw: UserRoleWithRole | UserRoleSelect | null): UserRole | null {
    if (!raw) return null;

    let roleDomain;
    if ('role' in raw && raw.role) {
        roleDomain = new Role(raw.role.id, raw.role.name, raw.role.description || undefined);
    }

    return new UserRole(
      Number(raw.userId),
      raw.roleId,
      raw.assignedBy ? Number(raw.assignedBy) : undefined,
      raw.expiresAt || undefined,
      raw.assignedAt || undefined,
      roleDomain
    );
  }

  static toUserRolePersistence(domain: UserRole): InferInsertModel<typeof userRoles> {
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

success "✅ RBAC MAPPER RESTORED SUCCESSFULLY!"
echo "👉 App should compile cleanly now: npm run start:dev"
