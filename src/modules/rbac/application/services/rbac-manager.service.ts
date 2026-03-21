import { Injectable, Inject, Logger } from '@nestjs/common';
import {
  IRoleRepository,
  IPermissionRepository,
} from '../../domain/repositories/rbac.repository';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';
import { IFileParser } from '@core/shared/application/ports/file-parser.port';

// Helper type for CSV Row
type RbacCsvRow = {
  role: string;
  resource: string;
  action: string;
  attributes: string;
  description: string;
};


@Injectable()
export class RbacManagerService {
  private readonly logger = new Logger(RbacManagerService.name);

  constructor(
    @Inject(IRoleRepository) private roleRepo: IRoleRepository,
    @Inject(IPermissionRepository) private permRepo: IPermissionRepository,
    @Inject(IFileParser) private fileParser: IFileParser, // Injected Parser
  ) { }

  async importFromCsv(csvBuffer: Buffer): Promise<any> {
    // 1. Dùng Adapter xịn để parse CSV thành mảng Objects
    const records = await this.fileParser.parseCsvAsync<RbacCsvRow>(csvBuffer);

    // ✅ THÊM LOG ĐỂ DEBUG
    this.logger.debug(`[CSV Import] Đã parse được: ${records.length} dòng.`);
    if (records.length > 0) {
      this.logger.debug(`[CSV Import] Dữ liệu mẫu dòng 1: ${JSON.stringify(records[0])}`);
    }

    let createdCount = 0;
    let updatedCount = 0;

    for (const row of records) {
      // 2. Lấy data từ Object (Rất an toàn, không sợ phẩy trong ngoặc kép nữa)
      const { role: roleName, resource, action, attributes, description } = row;

      // ✅ THÊM LOG ĐỂ XEM CÓ BỊ SKIP KHÔNG
      if (!roleName || !resource) {
        this.logger.warn(`[CSV Import] Bỏ qua dòng do thiếu role hoặc resource: ${JSON.stringify(row)}`);
        continue;
      }

      const permName = resource === '*' ? 'manage:all' : `${resource}:${action}`;

      // Xử lý Permission
      let perm = await this.permRepo.findByName(permName);
      if (!perm) {
        perm = new Permission({
          name: permName,
          description: description || '',
          resourceType: resource,
          action: action,
          isActive: true,
          attributes: attributes || '*',
        });

        perm = await this.permRepo.save(perm);
        createdCount++;
      }

      // Xử lý Role
      let role = await this.roleRepo.findByName(roleName);
      if (!role) {
        role = new Role({
          name: roleName,
          description: 'Imported from CSV',
          isActive: true,
          isSystem: false,
          permissions: []
        });

        role = await this.roleRepo.save(role);
      }

      // Gán quyền vào Role
      if (!role.permissions) role.permissions = [];
      const hasPerm = role.permissions.some((p) => p.name === perm!.name);

      if (!hasPerm) {
        role.permissions.push(perm!);
        await this.roleRepo.save(role);
        updatedCount++;
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
