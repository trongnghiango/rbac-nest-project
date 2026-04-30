import { Injectable, Logger, Inject } from '@nestjs/common';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { eq, and } from 'drizzle-orm';
import * as bcrypt from 'bcrypt';

@Injectable()
export class StaxLegacyMigrationService {
    private readonly logger = new Logger(StaxLegacyMigrationService.name);

    // Dùng Map để làm buffer chống trùng lặp trong bộ nhớ (Deduplication Buffer)
    private orgUnitMap = new Map<string, number>();
    private jobTitleMap = new Map<string, number>();
    private gradeMap = new Map<number, number>();
    private positionMap = new Map<string, number>();
    private roleMap = new Map<string, number>();

    constructor(
        @Inject(DRIZZLE) private readonly db: NodePgDatabase<typeof schema>
    ) { }

    /**
     * GIAI ĐOẠN 1: DI CƯ NHÂN SỰ (EMPLOYEES)
     */
    async migrateEmployees(rawData: any[], staxOrgId: number) {
        this.logger.log(`🚀 Bắt đầu di cư ${rawData.length} bản ghi nhân sự...`);
        let statistics = { success: 0, failed: 0, existing: 0 };

        // 1. Load các Roles hiện có vào Cache
        await this.loadRolesToCache();

        for (const row of rawData) {
            try {
                // Kiểm tra xem nhân sự đã tồn tại chưa (qua Mã NV)
                const existing = await this.db.query.employees.findFirst({
                    where: eq(schema.employees.employeeCode, row.maNv)
                });

                if (existing) {
                    statistics.existing++;
                    continue;
                }

                await this.db.transaction(async (tx) => {
                    // Bước A: Đảm bảo Cơ cấu tổ chức (OrgUnit, Position...) luôn sẵn sàng
                    const positionId = await this.ensureOrgStructure(tx, staxOrgId, {
                        deptName: row.phongBan,
                        jobTitle: row.chucVu,
                        gradeLevel: row.capBac
                    });

                    // Bước B: Tạo Tài khoản User (RBAC)
                    const userId = await this.ensureUserAccount(tx, {
                        username: row.email?.split('@')[0] || row.maNv.toLowerCase(),
                        email: row.email,
                        fullName: row.ten,
                        roleName: this.inferRoleFromTitle(row.chucVu)
                    });

                    // Bước C: Tạo thực thể Employee
                    await tx.insert(schema.employees).values({
                        organizationId: staxOrgId,
                        userId: userId,
                        employeeCode: row.maNv,
                        fullName: row.ten,
                        phoneNumber: row.sdt,
                        positionId: positionId,
                        joinDate: row.start, // Cần format chuẩn date
                        status: this.mapStatus(row.tinhTrang),
                        metadata: {
                            legacy_data: row, // Lưu toàn bộ dòng excel tham lam vào jsonb
                            migration_date: new Date().toISOString()
                        },
                        remarks: row.ghiChu
                    });
                });

                statistics.success++;
            } catch (error) {
                this.logger.error(`❌ Lỗi tại dòng [${row.maNv} - ${row.ten}]: ${error.message}`);
                statistics.failed++;
            }
        }

        return statistics;
    }

    // --- LOGIC HỖ TRỢ (PRIVATE METHODS) ---

    private async loadRolesToCache() {
        const allRoles = await this.db.query.roles.findMany();
        allRoles.forEach((r: any) => this.roleMap.set(r.name, r.id));
    }

    private inferRoleFromTitle(title: string): string {
        const t = title.toUpperCase();
        if (t.includes('GIÁM ĐỐC') || t.includes('LEADER')) return 'MANAGER';
        if (t.includes('KẾ TOÁN')) return 'ACCOUNTANT';
        return 'STAFF';
    }

    private mapStatus(status: string) {
        if (!status) return 'ACTIVE';
        const s = status.toUpperCase();
        if (s.includes('WORKING')) return 'ACTIVE';
        if (s.includes('LEFT')) return 'RESIGNED';
        return 'OTHER';
    }

    private async ensureOrgStructure(tx: any, staxOrgId: number, info: { deptName: string, jobTitle: string, gradeLevel: number }) {
        // 1. Phẫu thuật Phòng ban (OrgUnit)
        let orgUnitId = this.orgUnitMap.get(info.deptName);
        if (!orgUnitId) {
            const [unit] = await tx.insert(schema.orgUnits).values({
                organizationId: staxOrgId,
                name: info.deptName,
                code: info.deptName.toUpperCase().replace(/\s/g, '_'),
                type: 'DEPARTMENT'
            }).onConflictDoNothing().returning();
            
            // Nếu conflict, query lại lấy ID
            if (!unit) {
                const existingUnit = await tx.query.orgUnits.findFirst({
                    where: eq(schema.orgUnits.name, info.deptName)
                });
                orgUnitId = existingUnit.id;
            } else {
                orgUnitId = unit.id;
            }
            this.orgUnitMap.set(info.deptName, orgUnitId!);
        }

        // 2. Chức danh (JobTitle)
        let jobTitleId = this.jobTitleMap.get(info.jobTitle);
        if (!jobTitleId) {
            const [jt] = await tx.insert(schema.jobTitles).values({
                name: info.jobTitle
            }).onConflictDoNothing().returning();
            
            if (!jt) {
                const existingJt = await tx.query.jobTitles.findFirst({
                    where: eq(schema.jobTitles.name, info.jobTitle)
                });
                jobTitleId = existingJt.id;
            } else {
                jobTitleId = jt.id;
            }
            this.jobTitleMap.set(info.jobTitle, jobTitleId!);
        }

        // 3. Cấp bậc (Grade) - Giả định Rank là số nguyên (1, 2, 3...)
        let gradeId = this.gradeMap.get(info.gradeLevel);
        if (!gradeId && info.gradeLevel) {
            const [gr] = await tx.insert(schema.grades).values({
                levelNumber: info.gradeLevel,
                code: `GR_${info.gradeLevel}`,
                name: `Cấp bậc ${info.gradeLevel}`
            }).onConflictDoNothing().returning();

           if (gr) gradeId = gr.id;
           else {
               const existingGr = await tx.query.grades.findFirst({
                   where: eq(schema.grades.levelNumber, info.gradeLevel)
               });
               gradeId = existingGr.id;
           }
           this.gradeMap.set(info.gradeLevel, gradeId!);
        }

        // 4. Vị trí ĐỊNH BIÊN (Position) - Kết hợp 3 cái trên
        const posKey = `${orgUnitId}-${jobTitleId}-${gradeId}`;
        let positionId = this.positionMap.get(posKey);
        if (!positionId) {
            const [pos] = await tx.insert(schema.positions).values({
                code: `POS-${info.deptName.substring(0,3).toUpperCase()}-${info.gradeLevel || 0}-${Date.now()}`,
                name: `${info.jobTitle} - ${info.deptName}`,
                orgUnitId: orgUnitId,
                jobTitleId: jobTitleId,
                gradeId: gradeId || 1 // Mặc định bậc 1 nếu không có
            }).returning();
            positionId = pos.id;
            this.positionMap.set(posKey, positionId!);
        }

        return positionId!;
    }

    private async ensureUserAccount(tx: any, info: { username: string, email: string, fullName: string, roleName: string }) {
        const hashedPassword = await bcrypt.hash(process.env.SEED_DEFAULT_PASSWORD || 'Stax@123', 10);
        
        let user = await tx.query.users.findFirst({
            where: eq(schema.users.username, info.username)
        });

        if (!user) {
            [user] = await tx.insert(schema.users).values({
                username: info.username,
                email: info.email,
                hashedPassword: hashedPassword
            }).returning();

            // Gán Role RBAC
            const roleId = this.roleMap.get(info.roleName);
            if (roleId) {
                await tx.insert(schema.userRoles).values({
                    userId: user.id,
                    roleId: roleId
                });
            }
        }

        return user.id;
    }
}
