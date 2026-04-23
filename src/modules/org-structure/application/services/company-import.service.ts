import { Injectable, Inject, Logger } from '@nestjs/common';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { IFileParser } from '@core/shared/application/ports/file-parser.port';
import { PasswordUtil } from '@core/shared/utils/password.util';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { eq, inArray } from 'drizzle-orm';

export type CoreEmployeeCsvRow = {
    username: string;
    email: string;
    fullName: string;
    employeeCode: string;
    locationCode: string;
    departmentCode: string;
    departmentName: string;
    positionName: string;
    jobTitle: string;
    gradeLevel: number;
    role: string;
};

@Injectable()
export class CompanyImportService {
    private readonly logger = new Logger(CompanyImportService.name);

    constructor(
        @Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>,
        @Inject(ITransactionManager) private txManager: ITransactionManager,
        @Inject(IFileParser) private fileParser: IFileParser,
    ) { }

    // THÊM THAM SỐ: organizationId
    async importCoreCompany(csvBuffer: Buffer, adminId: number, organizationId: number) {
        const records = await this.fileParser.parseCsvAsync<CoreEmployeeCsvRow>(csvBuffer);
        if (!records.length) return { success: false as const, message: 'File CSV rỗng' };

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

        return await this.txManager.runInTransaction(async () => {

            if (locations.size > 0) {
                await this.db.insert(schema.locations).values(Array.from(locations).map(l => ({ code: l, name: l }))).onConflictDoNothing({ target: schema.locations.code });
            }
            const locsDb = await this.db.select().from(schema.locations).where(inArray(schema.locations.code, Array.from(locations)));
            const locMap = new Map(locsDb.map(l => [l.code, l.id]));

            if (grades.size > 0) {
                await this.db.insert(schema.grades).values(Array.from(grades).map(g => ({ levelNumber: g, code: `BAC_${g}`, name: `Bậc ${g}` }))).onConflictDoNothing({ target: schema.grades.code });
            }
            const gradesDb = await this.db.select().from(schema.grades).where(inArray(schema.grades.levelNumber, Array.from(grades)));
            const gradeMap = new Map(gradesDb.map(g => [g.levelNumber, g.id]));

            if (jobTitles.size > 0) {
                await this.db.insert(schema.jobTitles).values(Array.from(jobTitles).map(name => ({ name }))).onConflictDoNothing({ target: schema.jobTitles.name });
            }
            const titlesDb = await this.db.select().from(schema.jobTitles).where(inArray(schema.jobTitles.name, Array.from(jobTitles)));
            const titleMap = new Map(titlesDb.map(t => [t.name, t.id]));

            // TẠO PHÒNG BAN GẮN VỚI TỔ CHỨC
            const orgUnitInserts = Array.from(departments.entries()).map(([code, name]) => ({
                organizationId: organizationId, // <--- THÊM VÀO ĐÂY
                code,
                name: name || code,
                type: code === 'HQ' ? 'COMPANY' : 'DEPARTMENT',
            }));

            if (orgUnitInserts.length > 0) {
                await this.db.insert(schema.orgUnits).values(orgUnitInserts).onConflictDoNothing({ target: schema.orgUnits.code });
            }

            const orgsDb = await this.db.select().from(schema.orgUnits).where(inArray(schema.orgUnits.code, Array.from(departments.keys())));
            const orgMap = new Map(orgsDb.map(o => [o.code, o.id]));

            let successCount = 0;

            for (const row of records) {
                const orgId = orgMap.get(row.departmentCode);
                const titleId = titleMap.get(row.jobTitle);
                const gradeId = gradeMap.get(Number(row.gradeLevel));

                if (!orgId || !titleId || !gradeId) continue;

                const posCode = `POS-${row.departmentCode}-${row.gradeLevel}`;
                let position = await this.db.query.positions.findFirst({ where: eq(schema.positions.code, posCode) });

                if (!position) {
                    const [newPos] = await this.db.insert(schema.positions).values({
                        code: posCode,
                        name: row.positionName || row.jobTitle,
                        orgUnitId: orgId,
                        jobTitleId: titleId,
                        gradeId: gradeId,
                        headcountLimit: 10,
                    }).returning();
                    position = newPos;
                }

                const existingUser = await this.db.query.users.findFirst({ where: eq(schema.users.username, row.username) });
                let userId: number;

                if (!existingUser) {
                    const [newUser] = await this.db.insert(schema.users).values({
                        username: row.username,
                        email: row.email ? row.email.trim() : null, // <--- SỬA DÒNG NÀY (Nếu rỗng thì đổi thành null)
                        hashedPassword: defaultPassword,
                        isActive: true,
                    }).returning({ id: schema.users.id });
                    userId = newUser.id;

                    // TẠO NHÂN VIÊN GẮN VỚI TỔ CHỨC
                    await this.db.insert(schema.employees)
                        .values({
                            organization_id: organizationId,
                            userId: userId,
                            employeeCode: row.employeeCode,
                            fullName: row.fullName,
                            locationId: locMap.get(row.locationCode) || null,
                            positionId: position.id,
                        })
                        .onConflictDoUpdate({
                            target: schema.employees.employeeCode, // Nếu trùng Mã nhân viên
                            set: {
                                fullName: row.fullName, // Cập nhật lại tên mới
                                userId: userId,         // Gắn lại user id mới
                                positionId: position.id,
                                locationId: locMap.get(row.locationCode) || null,
                                updatedAt: new Date()
                            }
                        });
                    // await this.db.insert(schema.employees).values({
                    //     organization_id: organizationId, // <--- THÊM VÀO ĐÂY
                    //     userId: userId,
                    //     employeeCode: row.employeeCode,
                    //     fullName: row.fullName,
                    //     locationId: locMap.get(row.locationCode) || null,
                    //     positionId: position.id,
                    // });
                    successCount++;
                } else {
                    userId = existingUser.id;
                }

                if (row.role) {
                    const roleDb = await this.db.query.roles.findFirst({ where: eq(schema.roles.name, row.role) });
                    if (roleDb) {
                        await this.db.insert(schema.userRoles).values({ userId: userId, roleId: roleDb.id, assignedBy: adminId }).onConflictDoNothing();
                    }
                }
            }

            return {
                success: true as const,
                message: 'Khởi tạo cấu trúc nhân sự thành công!',
                stats: { employeesImported: successCount },
            };
        });
    }
}
