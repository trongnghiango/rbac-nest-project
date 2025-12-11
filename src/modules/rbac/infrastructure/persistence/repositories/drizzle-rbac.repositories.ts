import { Injectable } from '@nestjs/common';
import { eq, inArray, and } from 'drizzle-orm';
import {
  IRoleRepository,
  IPermissionRepository,
  IUserRoleRepository,
} from '../../../domain/repositories/rbac-repository.interface';
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';
import { DrizzleBaseRepository } from '../../../../../core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  roles,
  permissions,
  userRoles,
  rolePermissions,
} from '../../../../../database/schema';
import { RbacMapper } from '../mappers/rbac.mapper';
import { Transaction } from '../../../../../core/shared/application/ports/transaction-manager.port';

// --- ROLE REPOSITORY ---
@Injectable()
export class DrizzleRoleRepository
  extends DrizzleBaseRepository
  implements IRoleRepository
{
  async findByName(name: string, tx?: Transaction): Promise<Role | null> {
    const db = this.getDb(tx);
    const result = await db.query.roles.findFirst({
      where: eq(roles.name, name),
      with: {
        permissions: {
          with: { permission: true },
        },
      },
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
        const res = await trx
          .insert(roles)
          .values(insertData)
          .returning({ id: roles.id });
        savedRoleId = res[0].id;
      }

      // Handle Permissions Relation
      if (role.permissions && role.permissions.length > 0) {
        await trx
          .delete(rolePermissions)
          .where(eq(rolePermissions.roleId, savedRoleId));

        const permInserts = role.permissions.map((p) => ({
          roleId: savedRoleId,
          permissionId: p.id!,
        }));

        if (permInserts.length > 0) {
          await trx.insert(rolePermissions).values(permInserts);
        }
      }

      // Return full object by refetching
      const finalRole = await this.findByName(
        role.name,
        trx as unknown as Transaction,
      );
      return finalRole!;
    });
  }

  async findAllWithPermissions(
    roleIds: number[],
    tx?: Transaction,
  ): Promise<Role[]> {
    const db = this.getDb(tx);
    const results = await db.query.roles.findMany({
      where: inArray(roles.id, roleIds),
      with: { permissions: { with: { permission: true } } },
    });
    return results.map((r) => RbacMapper.toRoleDomain(r as any)!);
  }

  async findAll(tx?: Transaction): Promise<Role[]> {
    const db = this.getDb(tx);

    // Câu query này yêu cầu:
    // 1. roles -> quan hệ 'permissions' (trong rolesRelations) => trỏ tới bảng rolePermissions
    // 2. rolePermissions -> quan hệ 'permission' (trong rolePermissionsRelations) => trỏ tới bảng permissions
    const results = await db.query.roles.findMany({
      with: {
        permissions: {
          with: {
            permission: true,
          },
        },
      },
    });

    // Ép kiểu any ở đây là an toàn nếu Mapper xử lý tốt null/undefined
    return results.map((r) => RbacMapper.toRoleDomain(r as any)!);
  }

  async findAllOld(tx?: Transaction): Promise<Role[]> {
    const db = this.getDb(tx);
    const results = await db.query.roles.findMany({
      with: { permissions: { with: { permission: true } } },
    });
    return results.map((r) => RbacMapper.toRoleDomain(r as any)!);
  }
}

// --- PERMISSION REPOSITORY ---
@Injectable()
export class DrizzlePermissionRepository
  extends DrizzleBaseRepository
  implements IPermissionRepository
{
  async findByName(name: string, tx?: Transaction): Promise<Permission | null> {
    const db = this.getDb(tx);
    const result = await db
      .select()
      .from(permissions)
      .where(eq(permissions.name, name));
    return RbacMapper.toPermissionDomain(result[0]);
  }

  async save(permission: Permission, tx?: Transaction): Promise<Permission> {
    const db = this.getDb(tx);
    const data = RbacMapper.toPermissionPersistence(permission);

    let result;
    if (data.id) {
      result = await db
        .update(permissions)
        .set(data)
        .where(eq(permissions.id, data.id))
        .returning();
    } else {
      const { id, ...insertData } = data;
      result = await db.insert(permissions).values(insertData).returning();
    }

    return RbacMapper.toPermissionDomain(result[0])!;
  }

  async findAll(tx?: Transaction): Promise<Permission[]> {
    const db = this.getDb(tx);
    const results = await db.select().from(permissions);
    return results.map((r) => RbacMapper.toPermissionDomain(r)!);
  }
}

// --- USER ROLE REPOSITORY ---
@Injectable()
export class DrizzleUserRoleRepository
  extends DrizzleBaseRepository
  implements IUserRoleRepository
{
  async findByUserId(userId: number, tx?: Transaction): Promise<UserRole[]> {
    const db = this.getDb(tx);
    const results = await db.query.userRoles.findMany({
      where: eq(userRoles.userId, userId),
      with: { role: true },
    });
    return results.map((r) => RbacMapper.toUserRoleDomain(r as any)!);
  }

  async save(userRole: UserRole, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    const data = RbacMapper.toUserRolePersistence(userRole);

    // Manual Upsert for Composite Key
    await db
      .insert(userRoles)
      .values(data)
      .onConflictDoUpdate({
        target: [userRoles.userId, userRoles.roleId],
        set: { expiresAt: data.expiresAt, assignedBy: data.assignedBy },
      });
  }

  async findOne(
    userId: number,
    roleId: number,
    tx?: Transaction,
  ): Promise<UserRole | null> {
    const db = this.getDb(tx);
    const result = await db.query.userRoles.findFirst({
      where: and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)),
      with: { role: true },
    });
    return result ? RbacMapper.toUserRoleDomain(result as any) : null;
  }

  async delete(
    userId: number,
    roleId: number,
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);
    await db
      .delete(userRoles)
      .where(and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)));
  }
}
