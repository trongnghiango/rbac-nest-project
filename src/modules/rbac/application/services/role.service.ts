import { Injectable, Inject } from '@nestjs/common';
import {
  IRoleRepository,
  IPermissionRepository,
} from '../../domain/repositories/rbac.repository';
import { Role } from '../../domain/entities/role.entity';

//
import { ICacheService } from '@core/shared/application/ports/cache.port';


export interface CreateRoleParams {
  name: string;
  description?: string;
  isSystem?: boolean;
}

export interface AccessControlItem {
  role: string;
  resource: string;
  action: string;
  attributes: string;
}

@Injectable()
export class RoleService {
  constructor(
    @Inject(IRoleRepository) private roleRepo: IRoleRepository,
    @Inject(IPermissionRepository) private permRepo: IPermissionRepository,
    @Inject(ICacheService) private cacheService: ICacheService,
  ) { }

  async createRole(data: CreateRoleParams): Promise<Role> {
    const existing = await this.roleRepo.findByName(data.name);
    if (existing) throw new Error('Role exists');
    const role = new Role(
      undefined,
      data.name,
      data.description,
      true,
      data.isSystem,
    );
    return this.roleRepo.save(role);
    // ✅ SAU NÀY NẾU BẠN VIẾT HÀM UPDATE ROLE, HÃY NHỚ GỌI HÀM RESET CACHE
    // await this.cacheService.reset(); // (Hoặc dùng pattern để xóa riêng rbac:permissions:*)
  }

  async findAllRoles(): Promise<Role[]> {
    return this.roleRepo.findAll();
  }

  async getAccessControlList(): Promise<AccessControlItem[]> {
    const roles = await this.roleRepo.findAll();
    const acl: AccessControlItem[] = [];
    roles.forEach((role) => {
      if (role.permissions) {
        role.permissions.forEach((p) => {
          acl.push({
            role: role.name.toLowerCase(),
            resource: p.resourceType || '*',
            action: p.action || '*',
            attributes: p.attributes,
          });
        });
      }
    });
    return acl;
  }
}
