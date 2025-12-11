import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';

@Injectable()
export class RbacManagerService {
  private readonly logger = new Logger(RbacManagerService.name);

  constructor(
    @InjectRepository(Role)
    private roleRepo: Repository<Role>,
    @InjectRepository(Permission)
    private permRepo: Repository<Permission>,
  ) {}

  // ==========================================
  // 1. CHỨC NĂNG IMPORT (UPLOAD)
  // ==========================================
  async importFromCsv(
    csvContent: string,
  ): Promise<{ created: number; updated: number }> {
    const lines = csvContent
      .split(/\r?\n/)
      .filter((line) => line.trim() !== '');
    // Bỏ dòng header nếu có
    if (lines[0].toLowerCase().includes('role')) {
      lines.shift();
    }

    let createdCount = 0;
    let updatedCount = 0;

    for (const line of lines) {
      // CSV format: role,resource,action,attributes,description
      const cols = line.split(',').map((c) => c.trim());

      if (cols.length < 3) continue;

      // Vẫn lấy biến attributes ra nhưng không dùng để lưu vào DB (vì DB ko có cột này)
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const [roleName, resource, action, _attributes, description] = cols;

      // 1. Xử lý Permission
      const permName =
        resource === '*' ? 'manage:all' : `${resource}:${action}`;
      let perm = await this.permRepo.findOne({ where: { name: permName } });

      if (!perm) {
        // Fix TS2769: Bỏ field 'attributes' khi create
        perm = this.permRepo.create({
          name: permName,
          resourceType: resource,
          action: action,
          description: description || '',
          isActive: true,
        });
        await this.permRepo.save(perm);
        createdCount++;
      } else {
        // Fix TS2339: Chỉ update description, bỏ qua attributes
        let isChanged = false;
        if (description && perm.description !== description) {
          perm.description = description;
          isChanged = true;
        }

        if (isChanged) {
          await this.permRepo.save(perm);
          updatedCount++;
        }
      }

      // 2. Xử lý Role
      let role = await this.roleRepo.findOne({
        where: { name: roleName },
        relations: ['permissions'],
      });

      if (!role) {
        role = this.roleRepo.create({
          name: roleName,
          description: 'Imported from CSV',
          isActive: true,
          permissions: [],
        });
        await this.roleRepo.save(role);
      }

      // 3. Gán quyền vào Role
      if (!role.permissions) role.permissions = [];
      // Fix ESLint unnecessary assertion: perm chắc chắn tồn tại ở đây
      const hasPerm = role.permissions.some((p) => p.id === perm.id);

      if (!hasPerm) {
        role.permissions.push(perm);
        await this.roleRepo.save(role);
      }
    }

    this.logger.log(
      `Import finished. Created: ${createdCount}, Updated: ${updatedCount}`,
    );
    return { created: createdCount, updated: updatedCount };
  }

  // ==========================================
  // 2. CHỨC NĂNG EXPORT (DOWNLOAD)
  // ==========================================
  async exportToCsv(): Promise<string> {
    const roles = await this.roleRepo.find({
      relations: ['permissions'],
      order: { name: 'ASC' },
    });

    let csvContent = 'role,resource,action,attributes,description\n';

    for (const role of roles) {
      if (!role.permissions || role.permissions.length === 0) {
        csvContent += `${role.name},,,,\n`;
        continue;
      }

      for (const perm of role.permissions) {
        const desc =
          perm.description && perm.description.includes(',')
            ? `"${perm.description}"`
            : perm.description || '';

        const line = [
          role.name,
          perm.resourceType || '*',
          perm.action || '*',
          '*', // Fix TS2339: Hardcode attributes là '*' vì DB không lưu
          desc,
        ].join(',');

        csvContent += line + '\n';
      }
    }

    return csvContent;
  }
}
