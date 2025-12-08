import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  SystemRole,
  SystemPermission,
} from '../../domain/constants/rbac.constants';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';

// 1. Thêm cái này ngay bên trên class RoleService hoặc đầu file
export interface AccessControlItem {
  role: string;
  resource: string;
  action: string;
  attributes: string;
}

@Injectable()
export class RoleService {
  constructor(
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
  ) {}

  async createRole(data: {
    name: string;
    description?: string;
    isSystem?: boolean;
  }): Promise<Role> {
    const existing = await this.roleRepository.findOne({
      where: { name: data.name },
    });

    if (existing) {
      throw new Error(`Role ${data.name} already exists`);
    }

    const role = this.roleRepository.create({
      name: data.name,
      description: data.description,
      isSystem: data.isSystem || false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    return this.roleRepository.save(role);
  }

  async assignPermissionToRole(
    roleId: number,
    permissionId: number,
  ): Promise<void> {
    const role = await this.roleRepository.findOne({
      where: { id: roleId },
      relations: ['permissions'],
    });

    if (!role) {
      throw new Error('Role not found');
    }

    const permission = await this.permissionRepository.findOne({
      where: { id: permissionId },
    });

    if (!permission) {
      throw new Error('Permission not found');
    }

    if (!role.permissions) role.permissions = [];

    const alreadyHas = role.permissions.some((p) => p.id === permissionId);
    if (!alreadyHas) {
      role.permissions.push(permission);
      role.updatedAt = new Date();
      await this.roleRepository.save(role);
    }
  }

  async getRoleWithPermissions(roleName: string): Promise<Role | null> {
    return this.roleRepository.findOne({
      where: { name: roleName },
      relations: ['permissions'],
    });
  }

  async initializeSystemRoles(): Promise<void> {
    const systemRoles = Object.values(SystemRole);

    for (const roleName of systemRoles) {
      const existing = await this.roleRepository.findOne({
        where: { name: roleName },
      });

      if (!existing) {
        await this.createRole({
          name: roleName,
          description: `System role: ${roleName}`,
          isSystem: true,
        });
      }
    }
  }

  async initializeSystemPermissions(): Promise<void> {
    const systemPermissions = Object.values(SystemPermission);

    for (const permName of systemPermissions) {
      const existing = await this.permissionRepository.findOne({
        where: { name: permName },
      });

      if (!existing) {
        const [resource, action] = permName.split(':');

        await this.permissionRepository.save({
          name: permName,
          description: `Permission: ${permName}`,
          resourceType: resource,
          action: action,
          isActive: true,
          createdAt: new Date(),
        });
      }
    }
  }

  async getAccessControlList(): Promise<AccessControlItem[]> {
    // Lấy Role kèm theo Permission
    const roles = await this.roleRepository.find({
      relations: ['permissions'],
      where: { isActive: true },
    });

    const accessControlList: AccessControlItem[] = [];

    roles.forEach((role) => {
      if (role.permissions) {
        role.permissions.forEach((permission) => {
          // Logic: Nếu là ADMIN thì full quyền (*), user thì bị giới hạn (ví dụ mẫu)
          // Anh có thể sửa logic if/else ở đây tùy ý mà ko cần sửa DB
          let attributes = '*';

          // Ví dụ: Hardcode rule cho vui (hoặc để mặc định '*' hết cũng được)
          if (role.name === 'USER' && permission.resourceType === 'video') {
            attributes = '*, !views';
          }

          accessControlList.push({
            role: role.name.toLowerCase(),
            resource: permission.resourceType || 'all',
            action: permission.action || 'manage',
            attributes: attributes, // Giá trị tạo ra từ code
          });
        });
      }
    });

    return accessControlList;
  }
}
