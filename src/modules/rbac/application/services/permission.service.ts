import { Injectable, Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import type { Cache } from 'cache-manager';
import { UserRole } from '../../domain/entities/user-role.entity';
import { Role } from '../../domain/entities/role.entity';

@Injectable()
export class PermissionService {
  private readonly CACHE_TTL = 300; // 5 minutes
  private readonly CACHE_PREFIX = 'rbac:permissions:';

  constructor(
    @InjectRepository(UserRole)
    private userRoleRepository: Repository<UserRole>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async userHasPermission(
    userId: number,
    permissionName: string,
  ): Promise<boolean> {
    // Check cache first
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;
    const cached = await this.cacheManager.get<string[]>(cacheKey);

    if (cached) {
      return cached.includes(permissionName) || cached.includes('*');
    }

    // Get user's active roles
    // Join with role to ensure it exists and is valid
    const userRoles = await this.userRoleRepository.find({
      where: { userId },
      relations: ['role'],
    });

    const activeRoles = userRoles.filter(
      (ur) => ur.isActive() && ur.role.isActive,
    );
    const roleIds = activeRoles.map((ur) => ur.roleId);

    if (roleIds.length === 0) return false;

    // Get roles with permissions
    const roles = await this.roleRepository.find({
      where: { id: In(roleIds), isActive: true },
      relations: ['permissions'],
    });

    // Collect all permissions
    const permissions = new Set<string>();

    for (const role of roles) {
      if (role?.permissions) {
        role.permissions.forEach((p) => {
          if (p.isActive) {
            permissions.add(p.name);
          }
        });
      }
    }

    const permissionArray = Array.from(permissions);

    // Cache permissions
    await this.cacheManager.set(cacheKey, permissionArray, this.CACHE_TTL);

    return permissionArray.includes(permissionName);
  }

  async getUserPermissions(userId: number): Promise<string[]> {
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;

    // Try cache
    const cached = await this.cacheManager.get<string[]>(cacheKey);
    if (cached) return cached;

    // Query database
    const userRoles = await this.userRoleRepository.find({
      where: { userId },
      relations: ['role'],
    });

    const activeRoles = userRoles.filter((ur) => ur.isActive());
    const roleIds = activeRoles.map((ur) => ur.roleId);

    if (roleIds.length === 0) return [];

    const roles = await this.roleRepository.find({
      where: {
        id: In(roleIds),
        isActive: true,
      },
      relations: ['permissions'],
    });

    const permissions = new Set<string>();

    for (const role of roles) {
      if (role?.permissions) {
        role.permissions.forEach((p) => {
          if (p.isActive) {
            permissions.add(p.name);
          }
        });
      }
    }

    const permissionArray = Array.from(permissions);

    // Cache
    await this.cacheManager.set(cacheKey, permissionArray, this.CACHE_TTL);

    return permissionArray;
  }

  async getUserRoles(userId: number): Promise<string[]> {
    const userRoles = await this.userRoleRepository.find({
      where: { userId },
      relations: ['role'],
    });

    const activeRoles = userRoles.filter((ur) => ur.isActive());
    // Safe access to role name thanks to relation
    return activeRoles.map((ur) => ur.role.name);
  }

  async assignRole(
    userId: number,
    roleId: number,
    assignedBy: number,
  ): Promise<void> {
    const existing = await this.userRoleRepository.findOne({
      where: { userId, roleId },
    });

    if (existing) {
      throw new Error('User already has this role');
    }

    await this.userRoleRepository.save({
      userId,
      roleId,
      assignedBy,
      assignedAt: new Date(),
    });

    // Invalidate cache
    await this.cacheManager.del(`${this.CACHE_PREFIX}${userId}`);
  }

  async removeRole(userId: number, roleId: number): Promise<void> {
    await this.userRoleRepository.delete({ userId, roleId });
    await this.cacheManager.del(`${this.CACHE_PREFIX}${userId}`);
  }

  initializeDefaultData(): void {
    console.log('Initializing default RBAC data...');
  }
}
