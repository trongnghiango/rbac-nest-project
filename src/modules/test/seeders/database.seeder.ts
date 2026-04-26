import { Injectable, OnModuleInit, Inject, Logger } from '@nestjs/common';
import * as schema from '@database/schema';
import { eq } from 'drizzle-orm';
import * as bcrypt from 'bcrypt';
import * as fs from 'fs';
import * as path from 'path';
import { RbacManagerService } from '../../rbac/application/services/rbac-manager.service';
import { CompanyImportService } from '../../org-structure/application/services/company-import.service';
import { OrgStructureService } from '../../org-structure/application/services/org-structure.service';
import { IFileParser } from '@core/shared/application/ports/file-parser.port';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  private readonly logger = new Logger(DatabaseSeeder.name);
  private readonly seedDir = path.join(process.cwd(), 'database', 'seeds');

  constructor(
    private readonly rbacManagerService: RbacManagerService,
    private readonly companyImportService: CompanyImportService,
    private readonly orgStructureService: OrgStructureService,
    @Inject(IFileParser) private readonly fileParser: IFileParser,
    @Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>
  ) { }

  async onModuleInit() {
    if (process.env.RUN_SEEDS !== 'true') return;
    this.logger.log('🌱 Bắt đầu Seeding database...');
    try {
      await this.seedRbacRules();

      // BẮT BUỘC: Phải seed Tổ chức STAX trước
      const staxOrgId = await this.seedStaxOrganization();

      // Truyền ID của STAX xuống để gắn vào Nhân viên
      await this.seedSystemUsers(staxOrgId);
      await this.seedOrgUnits(staxOrgId);
      await this.seedCoreEmployees(staxOrgId);

      this.logger.log('✅ Database seeded successfully!');
    } catch (error) {
      this.logger.error('❌ Seeding failed:', error);
    }
  }

  private async seedRbacRules() {
    const filePath = path.join(this.seedDir, '01_rbac_rules.csv');
    if (!fs.existsSync(filePath)) return this.logger.warn('⚠️ Bỏ qua 01_rbac_rules.csv');
    const buffer = fs.readFileSync(filePath);
    const result = await this.rbacManagerService.importFromCsv(buffer);
    this.logger.log(` - 🛡️ RBAC: Tạo mới ${result.created}, cập nhật ${result.updated} quyền.`);
  }

  private async seedStaxOrganization(): Promise<number> {
    let staxOrg = await this.db.query.organizations.findFirst({
      where: eq(schema.organizations.isInternal, true)
    });

    if (!staxOrg) {
      const [newStax] = await this.db.insert(schema.organizations).values({
        companyName: 'STAX ENTERPRISE',
        taxCode: 'STAX-MASTER',
        type: 'ENTERPRISE',
        isInternal: true,
        status: 'ACTIVE'
      }).returning();
      this.logger.log(` - 🏢 Khởi tạo Master Organization (STAX) thành công! ID: ${newStax.id}`);
      return newStax.id;
    }

    this.logger.log(` - 🏢 Đã tìm thấy Master Organization (STAX). ID: ${staxOrg.id}`);
    return staxOrg.id;
  }

  private async seedSystemUsers(staxOrgId: number) {
    const hashedPassword = await bcrypt.hash('K@2026', 10);
    let existingUser = await this.db.query.users.findFirst({
      where: eq(schema.users.username, 'superadmin'),
    });
    let userId: number;

    if (!existingUser) {
      const [newUser] = await this.db
        .insert(schema.users)
        .values({
          username: 'superadmin',
          email: 'admin@test.com',
          hashedPassword: hashedPassword,
          isActive: true,
        })
        .returning({ id: schema.users.id });
      userId = newUser.id;

      // FIX LỖI TẠI ĐÂY: Truyền organizationId vào
      await this.db
        .insert(schema.employees)
        .values({
          organizationId: staxOrgId,
          userId: userId,
          employeeCode: 'ADMIN-001',
          fullName: 'Super Admin',
        });
      this.logger.log(' - Created Master User: superadmin');
    } else {
      userId = existingUser.id;
    }

    const superAdminRole = await this.db.query.roles.findFirst({
      where: eq(schema.roles.name, 'SUPER_ADMIN'),
    });
    if (superAdminRole) {
      await this.db
        .insert(schema.userRoles)
        .values({
          userId: userId,
          roleId: superAdminRole.id,
          assignedAt: new Date(),
        })
        .onConflictDoNothing();
      this.logger.log(` - 🔗 Đã gán Role [${superAdminRole.name}] cho User [superadmin]`);
    }
  }

  private async seedOrgUnits(staxOrgId: number) {
    const filePath = path.join(this.seedDir, '02_org_units.csv');
    if (!fs.existsSync(filePath)) return this.logger.warn('⚠️ Bỏ qua 02_org_units.csv');
    const buffer = fs.readFileSync(filePath);
    const records = await this.fileParser.parseCsvAsync<any>(buffer);
    const existingUnits = await this.orgStructureService.findAllUnits();
    const codeToIdMap = new Map<string, number>();
    existingUnits.forEach(u => codeToIdMap.set(u.code, u.id));
    let successCount = 0;

    for (const row of records) {
      if (codeToIdMap.has(row.code)) {
        successCount++;
        continue;
      }
      let parentId: number | undefined = undefined;
      if (row.parentCode) {
        parentId = codeToIdMap.get(row.parentCode);
      }
      try {
        const newUnit = await this.orgStructureService.createUnit({
          code: row.code,
          name: row.name,
          type: row.type,
          parentId: parentId,
          organizationId: staxOrgId // Truyền thêm organizationId
        } as any);
        codeToIdMap.set(row.code, newUnit.id);
        successCount++;
      } catch (error: any) {
        if (error.code !== '23505') {
          this.logger.error(`❌ Lỗi tạo OrgUnit ${row.code}: ${error.message}`);
        }
      }
    }
    this.logger.log(` - 🌳 Org Units: Đã dựng thành công sơ đồ tổ chức (${successCount} đơn vị).`);
  }

  private async seedCoreEmployees(staxOrgId: number) {
    const filePath = path.join(this.seedDir, '03_core_employees.csv');
    if (!fs.existsSync(filePath)) return this.logger.warn('⚠️ Bỏ qua 03_core_employees.csv');
    const buffer = fs.readFileSync(filePath);
    const result = await this.companyImportService.importCoreCompany(buffer, 1, staxOrgId);
    if (result.success) {
      this.logger.log(` - 🏢 Nhân sự: Import thành công ${result.stats.employeesImported} nhân sự.`);
    }
  }
}
