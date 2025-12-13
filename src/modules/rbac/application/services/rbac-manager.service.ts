import { Injectable, Inject, Logger } from '@nestjs/common';
// FIX IMPORT
import {
  IRoleRepository,
  IPermissionRepository,
} from '../../domain/repositories/rbac.repository';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';

@Injectable()
export class RbacManagerService {
  private readonly logger = new Logger(RbacManagerService.name);

  constructor(
    @Inject(IRoleRepository) private roleRepo: IRoleRepository, // FIX: Symbol
    @Inject(IPermissionRepository) private permRepo: IPermissionRepository, // FIX: Symbol
  ) {}

  async importFromCsv(csvContent: string): Promise<any> {
    const lines = csvContent
      .split(/\r?\n/)
      .filter((line) => line.trim() !== '');
    if (lines.length > 0 && lines[0].toLowerCase().includes('role')) {
      lines.shift();
    }

    let createdCount = 0;
    let updatedCount = 0;

    for (const line of lines) {
      const cols = line.split(',').map((c) => c.trim());
      if (cols.length < 3) continue;

      const [roleName, resource, action, attributes, description] = cols;
      const permName =
        resource === '*' ? 'manage:all' : `${resource}:${action}`;

      let perm = await this.permRepo.findByName(permName);
      if (!perm) {
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
      }

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

      if (!role.permissions) role.permissions = [];
      const hasPerm = role.permissions.some((p) => p.name === perm!.name);

      if (!hasPerm) {
        role.permissions.push(perm!);
        await this.roleRepo.save(role);
      }
    }
    return { created: createdCount, updated: updatedCount };
  }

  async exportToCsv(): Promise<string> {
    const roles = await this.roleRepo.findAll();
    const header = 'role,resource,action,attributes,description';
    const lines = [header];

    for (const role of roles) {
      if (!role.permissions || role.permissions.length === 0) {
        lines.push(`${role.name},,,,`);
        continue;
      }
      for (const perm of role.permissions) {
        const resource = perm.resourceType || '*';
        const action = perm.action || '*';
        const attributes = perm.attributes || '*';
        let desc = perm.description || '';
        if (desc.includes(',')) desc = `"${desc}"`;
        lines.push([role.name, resource, action, attributes, desc].join(','));
      }
    }
    return lines.join('\n');
  }
}
