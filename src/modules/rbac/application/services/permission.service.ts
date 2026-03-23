import { Injectable, Inject } from '@nestjs/common';
import {
  IUserRoleRepository,
  IRoleRepository,
} from '../../domain/repositories/rbac.repository';
// IMPORT Interface
import { ICacheService } from '@core/shared/application/ports/cache.port';
import { CORE_ROLES } from '@modules/rbac/domain/constants/rbac.constants';

@Injectable()
export class PermissionService {
  private readonly CACHE_TTL = 300; // Fallback nếu không truyền vào set()
  private readonly CACHE_PREFIX = 'rbac:permissions:';

  constructor(
    @Inject(IUserRoleRepository) private userRoleRepo: IUserRoleRepository,
    @Inject(IRoleRepository) private roleRepo: IRoleRepository,
    @Inject(ICacheService) private cacheService: ICacheService, // ✅ Inject Token
  ) { }

  async userHasPermission_old(
    userId: number,
    permissionName: string,
  ): Promise<boolean> {
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;

    // Sử dụng abstraction layer
    const cached = await this.cacheService.get<string[]>(cacheKey);

    if (cached) return cached.includes(permissionName) || cached.includes('*');

    const userRoles = await this.userRoleRepo.findByUserId(userId);
    const activeRoles = userRoles.filter(
      (ur) => ur.isActive() && ur.role?.isActive,
    );
    if (activeRoles.length === 0) return false;

    const roleIds = activeRoles.map((ur) => ur.roleId);
    const roles = await this.roleRepo.findAllWithPermissions(roleIds);

    const permissions = new Set<string>();
    roles.forEach((r) =>
      r.permissions?.forEach((p) => {
        if (p.isActive) permissions.add(p.name);
      }),
    );

    const permArray = Array.from(permissions);

    // Cache result
    await this.cacheService.set(cacheKey, permArray);
    // Mặc định adapter sẽ lấy TTL từ config nếu không truyền,
    // hoặc bạn có thể truyền this.CACHE_TTL vào tham số thứ 3

    return permArray.includes(permissionName);
  }

  async userHasPermission(userId: number, permissionName: string): Promise<boolean> {
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;

    // 1. Lấy từ Cache
    const cached = await this.cacheService.get<string[]>(cacheKey);

    if (cached) {
      // ✅ Bổ sung logic: Nếu trong cache có role SUPER_ADMIN hoặc quyền '*' -> Cho qua luôn
      if (cached.includes(CORE_ROLES.SUPER_ADMIN) || cached.includes('*') || cached.includes('manage:all')) {
        return true;
      }
      return cached.includes(permissionName);
    }

    // 2. Query DB nếu Cache Miss
    const userRoles = await this.userRoleRepo.findByUserId(userId);
    const activeRoles = userRoles.filter((ur) => ur.isActive() && ur.role?.isActive);

    if (activeRoles.length === 0) return false;

    // ✅ KIỂM TRA SUPER_ADMIN Bypass
    const isSuperAdmin = activeRoles.some(ur => ur.role?.name === CORE_ROLES.SUPER_ADMIN);

    const roleIds = activeRoles.map((ur) => ur.roleId);
    const roles = await this.roleRepo.findAllWithPermissions(roleIds);

    const permissions = new Set<string>();

    // Nếu là Super Admin, cache lại keyword nhận diện để lần sau bỏ qua nhanh
    if (isSuperAdmin) {
      permissions.add(CORE_ROLES.SUPER_ADMIN);
      permissions.add('*');
    } else {
      roles.forEach((r) =>
        r.permissions?.forEach((p) => {
          if (p.isActive) permissions.add(p.name); // Lưu string "module:action"
        }),
      );
    }

    const permArray = Array.from(permissions);

    // Lưu vào cache Redis
    await this.cacheService.set(cacheKey, permArray, this.CACHE_TTL);

    // Trả về kết quả
    if (isSuperAdmin) return true;
    // return permArray.includes(permissionName) || permArray.includes('*') || permArray.includes('manage:all');
    // ✅ NÂNG CẤP THÀNH CHECK WILDCARD ĐỘNG:
    if (permArray.includes('*') || permArray.includes('manage:all')) return true;
    if (permArray.includes(permissionName)) return true;

    // Logic phân tách (VD: 'rbac:manage' chia thành 'rbac' và 'manage')
    const [resource, action] = permissionName.split(':');

    // Kiểm tra xem user có quyền 'rbac:*' không
    if (resource && permArray.includes(`${resource}:*`)) return true;

    return false;
  }

  async assignRole(
    userId: number,
    roleId: number,
    assignedBy: number,
  ): Promise<void> {
    const existing = await this.userRoleRepo.findOne(userId, roleId);
    if (!existing) {
      const userRole: any = {
        userId,
        roleId,
        assignedBy,
        assignedAt: new Date(),
      };
      await this.userRoleRepo.save(userRole);

      // Invalidate cache
      await this.cacheService.del(`${this.CACHE_PREFIX}${userId}`);
    }
  }
}
