import { Injectable, Inject } from '@nestjs/common';
// FIX IMPORT
import {
  IRoleRepository,
  IPermissionRepository,
} from '../../domain/repositories/rbac.repository';
import { Role } from '../../domain/entities/role.entity';

export interface AccessControlItem {
  role: string;
  resource: string;
  action: string;
  attributes: string;
}

@Injectable()
export class RoleService {
  constructor(
    @Inject(IRoleRepository) private roleRepo: IRoleRepository, // FIX: Symbol
    @Inject(IPermissionRepository) private permRepo: IPermissionRepository, // FIX: Symbol
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
