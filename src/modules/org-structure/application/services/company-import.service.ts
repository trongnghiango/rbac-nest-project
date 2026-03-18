import { Injectable, Inject, Logger } from '@nestjs/common';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { IFileParser } from '@core/shared/application/ports/file-parser.port';
import { PasswordUtil } from '@core/shared/utils/password.util';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { eq, inArray, and } from 'drizzle-orm';

// Cấu trúc map 100% với File CSV mới
export type CoreEmployeeCsvRow = {
    username: string;
    email: string;
    fullName: string;
    employeeCode: string;
    locationCode: string;   // HCM, HQ
    departmentCode: string; // Mã phòng
    departmentName: string; // Tên phòng
    positionName: string;   // VD: "CV-IT", "Chuyên viên B2" (Tên hiển thị trong Hình 3)
    jobTitle: string;       // Tên chức danh chung (Trợ lý, Chuyên viên, Trưởng phòng)
    gradeLevel: number;     // 1, 2, ..., 10
    role: string;           // SUPER_ADMIN, STAFF...
};

@Injectable()
export class CompanyImportService {
    private readonly logger = new Logger(CompanyImportService.name);

    constructor(
        @Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>,
        @Inject(ITransactionManager) private txManager: ITransactionManager,
        @Inject(IFileParser) private fileParser: IFileParser,
    ) { }

    async importCoreCompany(csvBuffer: Buffer, adminId: number) {
        const records = await this.fileParser.parseCsvAsync<CoreEmployeeCsvRow>(csvBuffer);
        if (!records.length) return { success: false, message: 'File CSV rỗng' };

        // 1. Bóc tách dữ liệu Unique (Set/Map)
        const locations = new Set<string>();
        const departments = new Map<string, string>();
        const jobTitles = new Set<string>();
        const grades = new Set<number>();

        records.forEach((r) => {
            if (r.locationCode) locations.add(r.locationCode);
            if (r.departmentCode) departments.set(r.departmentCode, r.departmentName);
            if (r.jobTitle) jobTitles.add(r.jobTitle);
            if (r.gradeLevel) grades.add(Number(r.gradeLevel));
        });

        const defaultPassword = await PasswordUtil.hash('Company@2026');

        return await this.txManager.runInTransaction(async (tx: any) => {
            const dbTx = tx as NodePgDatabase<typeof schema>;

            // ==========================================
            // BƯỚC 1: UPSERT CÁC DANH MỤC CƠ SỞ (Từ điển)
            // ==========================================

            // 1.1 Locations
            if (locations.size > 0) {
                await dbTx.insert(schema.locations)
                    .values(Array.from(locations).map(l => ({ code: l, name: l })))
                    .onConflictDoNothing({ target: schema.locations.code });
            }
            const locsDb = await dbTx.select().from(schema.locations).where(inArray(schema.locations.code, Array.from(locations)));
            const locMap = new Map(locsDb.map(l => [l.code, l.id]));

            // 1.2 Grades (Bậc)
            if (grades.size > 0) {
                await dbTx.insert(schema.grades)
                    .values(Array.from(grades).map(g => ({ levelNumber: g, code: `BAC_${g}`, name: `Bậc ${g}` })))
                    .onConflictDoNothing({ target: schema.grades.code });
            }
            const gradesDb = await dbTx.select().from(schema.grades).where(inArray(schema.grades.levelNumber, Array.from(grades)));
            const gradeMap = new Map(gradesDb.map(g => [g.levelNumber, g.id]));

            // 1.3 Job Titles (Chức danh)
            if (jobTitles.size > 0) {
                await dbTx.insert(schema.jobTitles)
                    .values(Array.from(jobTitles).map(name => ({ name })))
                    .onConflictDoNothing({ target: schema.jobTitles.name });
            }
            const titlesDb = await dbTx.select().from(schema.jobTitles).where(inArray(schema.jobTitles.name, Array.from(jobTitles)));
            const titleMap = new Map(titlesDb.map(t => [t.name, t.id]));

            // 1.4 Org Units (Phòng ban)
            const orgUnitInserts = Array.from(departments.entries()).map(([code, name]) => ({
                code, name: name || code, type: code === 'HQ' ? 'COMPANY' : 'DEPARTMENT',
            }));
            if (orgUnitInserts.length > 0) {
                await dbTx.insert(schema.orgUnits).values(orgUnitInserts).onConflictDoNothing({ target: schema.orgUnits.code });
            }
            const orgsDb = await dbTx.select().from(schema.orgUnits).where(inArray(schema.orgUnits.code, Array.from(departments.keys())));
            const orgMap = new Map(orgsDb.map(o => [o.code, o.id]));

            // ==========================================
            // BƯỚC 2: TỰ ĐỘNG SINH MA TRẬN VỊ TRÍ (POSITIONS)
            // ==========================================
            let successCount = 0;

            for (const row of records) {
                const orgId = orgMap.get(row.departmentCode);
                const titleId = titleMap.get(row.jobTitle);
                const gradeId = gradeMap.get(Number(row.gradeLevel));

                if (!orgId || !titleId || !gradeId) continue;

                // Code duy nhất cho Vị trí (VD: POS-P_DICHVU-6)
                const posCode = `POS-${row.departmentCode}-${row.gradeLevel}`;

                // Kiểm tra Vị trí đã có chưa
                let position = await dbTx.query.positions.findFirst({
                    where: eq(schema.positions.code, posCode)
                });

                // Nếu chưa có, tạo Vị trí (Định biên) mới
                if (!position) {
                    const [newPos] = await dbTx.insert(schema.positions).values({
                        code: posCode,
                        name: row.positionName || row.jobTitle, // Tên riêng cho vị trí (VD: CV-IT)
                        orgUnitId: orgId,
                        jobTitleId: titleId,
                        gradeId: gradeId,
                        headcountLimit: 10, // Giả sử cho phép 10 người cùng vị trí này
                    }).returning();
                    position = newPos;
                }

                // ==========================================
                // BƯỚC 3: XỬ LÝ NHÂN VIÊN (USERS + EMPLOYEES)
                // ==========================================
                const existingUser = await dbTx.query.users.findFirst({
                    where: eq(schema.users.username, row.username),
                });

                let userId: number;

                if (!existingUser) {
                    // A. Tạo Identity
                    const [newUser] = await dbTx.insert(schema.users).values({
                        username: row.username,
                        email: row.email,
                        hashedPassword: defaultPassword,
                        isActive: true,
                    }).returning({ id: schema.users.id });
                    userId = newUser.id;

                    // B. Tạo Employee Profile (Liên kết vào ĐỊA ĐIỂM và VỊ TRÍ VỪA TẠO)
                    await dbTx.insert(schema.employees).values({
                        userId: userId,
                        employeeCode: row.employeeCode,
                        fullName: row.fullName,
                        locationId: locMap.get(row.locationCode) || null,
                        positionId: position.id, // Bổ nhiệm vào vị trí chuẩn
                    });

                    successCount++;
                } else {
                    userId = existingUser.id;
                }

                // ==========================================
                // BƯỚC 4: CẤP QUYỀN (RBAC)
                // ==========================================
                if (row.role) {
                    const roleDb = await dbTx.query.roles.findFirst({ where: eq(schema.roles.name, row.role) });
                    if (roleDb) {
                        await dbTx.insert(schema.userRoles)
                            .values({ userId: userId, roleId: roleDb.id, assignedBy: adminId })
                            .onConflictDoNothing();
                    }
                }
            }

            return {
                success: true,
                message: 'Khởi tạo cấu trúc nhân sự (Ma trận vị trí) thành công!',
                stats: { employeesImported: successCount },
            };
        });
    }
}
