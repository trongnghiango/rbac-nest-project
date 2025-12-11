import { Injectable, Inject } from '@nestjs/common';
import type {
  IRoleRepository,
  IPermissionRepository,
} from '../../domain/repositories/rbac-repository.interface'; // FIX: import type
import { Role } from '../../domain/entities/role.entity';
import {
  SystemRole,
  SystemPermission,
} from '../../domain/constants/rbac.constants';

export interface AccessControlItem {
  role: string;
  resource: string;
  action: string;
  attributes: string;
}

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

  async getAccessControlList(): Promise<AccessControlItem[]> {
    const roles = await this.roleRepo.findAll();
    const acl: AccessControlItem[] = [];
    roles.forEach((role) => {
      role.permissions.forEach((p) => {
        acl.push({
          role: role.name.toLowerCase(),
          resource: p.resourceType || '*',
          action: p.action || '*',
          attributes: p.attributes,
        });
      });
    });
    return acl;
  }

  // Seeder logic remains in seeder file mostly, but keeping init logic if needed
  async initializeSystemRoles(): Promise<void> {
    // Implementation placeholder if called from module init
  }
  async initializeSystemPermissions(): Promise<void> {
    // Implementation placeholder
  }
}
