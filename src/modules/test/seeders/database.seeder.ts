import { Injectable, OnModuleInit, Inject, Logger } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';

import { RbacManagerService } from '../../rbac/application/services/rbac-manager.service';
import { CompanyImportService } from '../../org-structure/application/services/company-import.service';
// 👉 Import thêm OrgStructureService
import { OrgStructureService } from '../../org-structure/application/services/org-structure.service';
// 👉 Import FileParser để đọc file org_units.csv
import { IFileParser } from '@core/shared/application/ports/file-parser.port';

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  private readonly logger = new Logger(DatabaseSeeder.name);
  private readonly seedDir = path.join(process.cwd(), 'database', 'seeds');

  constructor(
    private readonly rbacManagerService: RbacManagerService,
    private readonly companyImportService: CompanyImportService,
    private readonly orgStructureService: OrgStructureService, // 👉 Inject Service
    @Inject(IFileParser) private readonly fileParser: IFileParser, // 👉 Inject Parser
  ) { }

  async onModuleInit() {
    if (process.env.RUN_SEEDS !== 'true') return;

    this.logger.log('🌱 Bắt đầu Seeding database từ file CSV...');

    try {
      // THỨ TỰ THỰC THI BẮT BUỘC:
      await this.seedRbacRules();       // 1. Tạo Role
      await this.seedOrgUnits();        // 2. Vẽ Sơ đồ Tổ chức (Cây)
      await this.seedCoreEmployees();   // 3. Đổ nhân sự vào sơ đồ & Gán Role

      this.logger.log('✅ Database seeded successfully từ CSV!');
    } catch (error) {
      this.logger.error('❌ Seeding failed:', error);
    }
  }

  // 1. ĐỌC FILE RBAC
  private async seedRbacRules() {
    const filePath = path.join(this.seedDir, '01_rbac_rules.csv');
    if (!fs.existsSync(filePath)) return this.logger.warn('⚠️ Bỏ qua 01_rbac_rules.csv');

    const buffer = fs.readFileSync(filePath);
    const result = await this.rbacManagerService.importFromCsv(buffer);
    this.logger.log(` - 🛡️ RBAC: Tạo mới ${result.created}, cập nhật ${result.updated} quyền.`);
  }

  // 2. ĐỌC FILE SƠ ĐỒ TỔ CHỨC VÀ DỰNG CÂY
  private async seedOrgUnits() {
    const filePath = path.join(this.seedDir, '02_org_units.csv');
    if (!fs.existsSync(filePath)) return this.logger.warn('⚠️ Bỏ qua 02_org_units.csv');

    const buffer = fs.readFileSync(filePath);
    const records = await this.fileParser.parseCsvAsync<any>(buffer);

    // 1. Đồng bộ Map với dữ liệu đã có trong DB
    const existingUnits = await this.orgStructureService.findAllUnits();
    const codeToIdMap = new Map<string, number>();
    existingUnits.forEach(u => codeToIdMap.set(u.code, u.id));

    let successCount = 0;

    for (const row of records) {
      if (codeToIdMap.has(row.code)) {
        successCount++;
        continue;
      }

      // Tìm parentId nếu có parentCode
      let parentId: number | undefined = undefined;
      if (row.parentCode) {
        parentId = codeToIdMap.get(row.parentCode);
        if (!parentId) {
          this.logger.warn(`Lỗi OrgUnit: Không tìm thấy Parent Code '${row.parentCode}' cho '${row.code}'. Hãy xếp thằng Cha lên trên thằng Con trong file CSV!`);
          continue;
        }
      }

      try {
        // 👉 Gọi Service xịn của bạn để nó tự tạo DB và tính Path (/1/3/4/)
        const newUnit = await this.orgStructureService.createUnit({
          code: row.code,
          name: row.name,
          type: row.type,
          parentId: parentId,
        });

        // Lưu ID lại để lát nữa mấy thằng con tìm thấy
        codeToIdMap.set(row.code, newUnit.id);
        successCount++;
      } catch (error) {
        // Bỏ qua lỗi trùng mã (đã tồn tại) để lần khởi động sau không bị lỗi
        if (error.code !== '23505') {
          this.logger.error(`❌ Lỗi tạo OrgUnit ${row.code} (${row.name}): ${error.message}`, error.stack);
        }
      }
    }
    this.logger.log(` - 🌳 Org Units: Đã dựng thành công sơ đồ tổ chức (${successCount} đơn vị).`);
  }

  // 3. ĐỌC FILE NHÂN SỰ
  private async seedCoreEmployees() {
    const filePath = path.join(this.seedDir, '03_core_employees.csv');
    if (!fs.existsSync(filePath)) return this.logger.warn('⚠️ Bỏ qua 03_core_employees.csv');

    const buffer = fs.readFileSync(filePath);
    const result = await this.companyImportService.importCoreCompany(buffer, 1);

    if (result.success) {
      this.logger.log(` - 🏢 Nhân sự: Import thành công ${result.stats.employeesImported} nhân sự chủ chốt.`);
    }
  }
}