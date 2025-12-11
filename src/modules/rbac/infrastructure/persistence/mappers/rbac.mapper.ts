import { Role } from '../../../domain/entities/role.entity'; // FIX: 3 dots
import { Permission } from '../../../domain/entities/permission.entity'; // FIX: 3 dots
import { UserRole } from '../../../domain/entities/user-role.entity'; // FIX: 3 dots
import { RoleOrmEntity } from '../entities/role.orm-entity';
import { PermissionOrmEntity } from '../entities/permission.orm-entity';
import { UserRoleOrmEntity } from '../entities/user-role.orm-entity';

export class RbacMapper {
  // PERMISSION
  static toPermissionDomain(
    orm: PermissionOrmEntity | null,
  ): Permission | null {
    if (!orm) return null;
    return new Permission(
      orm.id,
      orm.name,
      orm.description || undefined,
      orm.resourceType || undefined,
      orm.action || undefined,
      orm.isActive,
      orm.attributes,
      orm.createdAt,
    );
  }
  static toPermissionPersistence(domain: Permission): PermissionOrmEntity {
    const orm = new PermissionOrmEntity();
    if (domain.id) orm.id = domain.id;
    orm.name = domain.name;
    orm.description = domain.description || null;
    orm.resourceType = domain.resourceType || null;
    orm.action = domain.action || null;
    orm.isActive = domain.isActive;
    orm.attributes = domain.attributes;
    orm.createdAt = domain.createdAt || new Date();
    return orm;
  }

  // ROLE
  static toRoleDomain(orm: RoleOrmEntity | null): Role | null {
    if (!orm) return null;
    const perms = orm.permissions
      ? orm.permissions.map((p) => this.toPermissionDomain(p)!).filter(Boolean)
      : [];
    return new Role(
      orm.id,
      orm.name,
      orm.description || undefined,
      orm.isActive,
      orm.isSystem,
      perms,
      orm.createdAt,
      orm.updatedAt,
    );
  }
  static toRolePersistence(domain: Role): RoleOrmEntity {
    const orm = new RoleOrmEntity();
    if (domain.id) orm.id = domain.id;
    orm.name = domain.name;
    orm.description = domain.description || null;
    orm.isActive = domain.isActive;
    orm.isSystem = domain.isSystem;
    orm.permissions = domain.permissions.map((p) =>
      this.toPermissionPersistence(p),
    );
    orm.createdAt = domain.createdAt || new Date();
    orm.updatedAt = domain.updatedAt || new Date();
    return orm;
  }

  // USER ROLE
  static toUserRoleDomain(orm: UserRoleOrmEntity | null): UserRole | null {
    if (!orm) return null;
    const role = orm.role ? this.toRoleDomain(orm.role) : undefined;
    return new UserRole(
      Number(orm.userId),
      orm.roleId,
      orm.assignedBy ? Number(orm.assignedBy) : undefined,
      orm.expiresAt || undefined,
      orm.assignedAt,
      role!,
    );
  }
  static toUserRolePersistence(domain: UserRole): UserRoleOrmEntity {
    const orm = new UserRoleOrmEntity();
    orm.userId = domain.userId;
    orm.roleId = domain.roleId;
    orm.assignedBy = domain.assignedBy || null;
    orm.expiresAt = domain.expiresAt || null;
    orm.assignedAt = domain.assignedAt || new Date();
    return orm;
  }
}
