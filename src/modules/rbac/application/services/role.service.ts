import { Injectable, Inject } from '@nestjs/common';
import type { IRoleRepository, IPermissionRepository } from '../../domain/repositories/rbac-repository.interface';
import { Role } from '../../domain/entities/role.entity';

// Interface cho hàm getAccessControlList (đã định nghĩa trước đó)
export interface AccessControlItem { role: string; resource: string; action: string; attributes: string; }

@Injectable()
export class RoleService {
  constructor(
    @Inject('IRoleRepository') private roleRepo: IRoleRepository,
    @Inject('IPermissionRepository') private permRepo: IPermissionRepository,
  ) {}

  async createRole(data: any): Promise<Role> {
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
  }

  // --- HÀM MỚI: Lấy danh sách Roles đầy đủ ---
  async findAllRoles(): Promise<Role[]> {
    return this.roleRepo.findAll();
  }
  // ------------------------------------------

  async getAccessControlList(): Promise<AccessControlItem[]> {
    const roles = await this.roleRepo.findAll();
    const acl: AccessControlItem[] = [];
    roles.forEach(role => {
        if (role.permissions) {
            role.permissions.forEach(p => {
                acl.push({
                    role: role.name.toLowerCase(),
                    resource: p.resourceType || '*',
                    action: p.action || '*',
                    attributes: p.attributes
                });
            });
        }
    });
    return acl;
  }

  async initializeSystemRoles(): Promise<void> {}
  async initializeSystemPermissions(): Promise<void> {}
}
