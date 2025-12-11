import { Injectable, Inject, Logger } from '@nestjs/common';
import type {
  IRoleRepository,
  IPermissionRepository,
} from '../../domain/repositories/rbac-repository.interface';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';

@Injectable()
export class RbacManagerService {
  private readonly logger = new Logger(RbacManagerService.name);

  constructor(
    @Inject('IRoleRepository') private roleRepo: IRoleRepository,
    @Inject('IPermissionRepository') private permRepo: IPermissionRepository,
  ) {}

  // Logic Import giữ nguyên (hoặc update full nếu cần)
  async importFromCsv(csvContent: string): Promise<any> {
    const lines = csvContent
      .split(/\r?\n/)
      .filter((line) => line.trim() !== '');
    if (lines.length > 0 && lines[0].toLowerCase().includes('role')) {
      lines.shift(); // Remove header
    }

    let createdCount = 0;
    let updatedCount = 0;

    for (const line of lines) {
      // CSV: role,resource,action,attributes,description
      const cols = line.split(',').map((c) => c.trim());
      if (cols.length < 3) continue;

      const [roleName, resource, action, attributes, description] = cols;

      // 1. Handle Permission
      const permName =
        resource === '*' ? 'manage:all' : `${resource}:${action}`;
      let perm = await this.permRepo.findByName(permName);

      if (!perm) {
        // Create new permission
        perm = new Permission(
          undefined,
          permName,
          description || '',
          resource,
          action,
          true,
          attributes || '*',
        );
        perm = await this.permRepo.save(perm);
        createdCount++;
      } else {
        // Update existing (optional logic)
        let changed = false;
        if (attributes && perm.attributes !== attributes) {
          perm.attributes = attributes;
          changed = true;
        }
        if (description && perm.description !== description) {
          perm.description = description;
          changed = true;
        }

        if (changed) {
          await this.permRepo.save(perm);
          updatedCount++;
        }
      }

      // 2. Handle Role
      let role = await this.roleRepo.findByName(roleName);
      if (!role) {
        role = new Role(
          undefined,
          roleName,
          'Imported from CSV',
          true,
          false,
          [],
        );
        role = await this.roleRepo.save(role);
      }

      // 3. Assign Permission to Role
      if (!role.permissions) role.permissions = [];
      const hasPerm = role.permissions.some((p) => p.name === perm!.name); // Domain logic check by name or ID

      if (!hasPerm) {
        role.permissions.push(perm!);
        await this.roleRepo.save(role);
      }
    }

    return { created: createdCount, updated: updatedCount };
  }

  // FIX: Logic Export đầy đủ
  async exportToCsv(): Promise<string> {
    // Repository phải đảm bảo load relation ['permissions']
    const roles = await this.roleRepo.findAll();

    const header = 'role,resource,action,attributes,description';
    const lines = [header];

    for (const role of roles) {
      if (!role.permissions || role.permissions.length === 0) {
        // Nếu Role không có quyền, in ra dòng rỗng để biết Role tồn tại
        lines.push(`${role.name},,,,`);
        continue;
      }

      for (const perm of role.permissions) {
        // Xử lý dữ liệu để tránh lỗi CSV
        const resource = perm.resourceType || '*';
        const action = perm.action || '*';
        const attributes = perm.attributes || '*';

        // Nếu description có dấu phẩy, bọc trong ngoặc kép
        let desc = perm.description || '';
        if (desc.includes(',')) {
          desc = `"${desc}"`;
        }

        const line = [role.name, resource, action, attributes, desc].join(',');

        lines.push(line);
      }
    }

    return lines.join('\n');
  }
}
