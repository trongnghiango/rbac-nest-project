import { InferSelectModel } from 'drizzle-orm';
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';
import { roles, permissions, userRoles } from '../../../../../database/schema';

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
      raw.createdAt || undefined,
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
  static toRoleDomain(
    raw: RoleWithPermissions | RoleRecord | null,
  ): Role | null {
    if (!raw) return null;

    // Check if it has nested permissions
    let perms: Permission[] = [];
    if ('permissions' in raw && Array.isArray(raw.permissions)) {
      perms = raw.permissions
        .map((rp) => this.toPermissionDomain(rp.permission)!)
        .filter(Boolean);
    }

    return new Role(
      raw.id,
      raw.name,
      raw.description || undefined,
      raw.isActive || false,
      raw.isSystem || false,
      perms,
      raw.createdAt || undefined,
      raw.updatedAt || undefined,
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
  static toUserRoleDomain(
    raw: UserRoleWithRole | UserRoleRecord | null,
  ): UserRole | null {
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
      role!,
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
