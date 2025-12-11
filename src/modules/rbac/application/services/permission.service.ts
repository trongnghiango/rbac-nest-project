import { Injectable, Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import type {
  IUserRoleRepository,
  IRoleRepository,
} from '../../domain/repositories/rbac-repository.interface'; // FIX: import type

@Injectable()
export class PermissionService {
  private readonly CACHE_TTL = 300;
  private readonly CACHE_PREFIX = 'rbac:permissions:';

  constructor(
    @Inject('IUserRoleRepository') private userRoleRepo: IUserRoleRepository,
    @Inject('IRoleRepository') private roleRepo: IRoleRepository,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async userHasPermission(
    userId: number,
    permissionName: string,
  ): Promise<boolean> {
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;
    const cached = await this.cacheManager.get<string[]>(cacheKey);
    if (cached) return cached.includes(permissionName) || cached.includes('*');

    const userRoles = await this.userRoleRepo.findByUserId(userId);
    // Note: Assuming repo returns domain objects with populated role (if implemented that way)
    // or we fetch roles separately. For simplicity assuming basic flow:

    if (userRoles.length === 0) return false;
    const roleIds = userRoles.map((ur) => ur.roleId);

    const roles = await this.roleRepo.findAllWithPermissions(roleIds);

    const permissions = new Set<string>();
    roles.forEach((r) =>
      r.permissions?.forEach((p) => {
        if (p.isActive) permissions.add(p.name);
      }),
    );

    const permArray = Array.from(permissions);
    await this.cacheManager.set(cacheKey, permArray, this.CACHE_TTL);
    return permArray.includes(permissionName);
  }

  async assignRole(
    userId: number,
    roleId: number,
    assignedBy: number,
  ): Promise<void> {
    const existing = await this.userRoleRepo.findOne(userId, roleId);
    if (!existing) {
      // Construct basic UserRole object
      const userRole: any = {
        userId,
        roleId,
        assignedBy,
        assignedAt: new Date(),
      };
      await this.userRoleRepo.save(userRole);
      await this.cacheManager.del(`${this.CACHE_PREFIX}${userId}`);
    }
  }
}
