// src/modules/org-structure/application/services/company-import.service.ts
import { Injectable, Inject, Logger } from '@nestjs/common';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { IFileParser } from '@core/shared/application/ports/file-parser.port';
import { PasswordUtil } from '@core/shared/utils/password.util';
import { IOrgStructureRepository } from '../../domain/repositories/org-structure.repository';
import { IUserRepository } from '@modules/user/domain/repositories/user.repository';
import { IEmployeeRepository } from '@modules/employee/domain/repositories/employee.repository';
import { IRoleRepository, IUserRoleRepository } from '@modules/rbac/domain/repositories/rbac.repository';
import { User } from '@modules/user/domain/entities/user.entity';
import { UserRole } from '@modules/rbac/domain/entities/user-role.entity';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { CoreEmployeeImportedEvent } from '@modules/org-structure/domain/events/core-employee-imported.event';

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
        @Inject(ITransactionManager) private readonly txManager: ITransactionManager,
        @Inject(IFileParser) private readonly fileParser: IFileParser,
        @Inject(IOrgStructureRepository) private readonly orgRepo: IOrgStructureRepository,
        @Inject(IUserRepository) private readonly userRepo: IUserRepository,
        @Inject(IRoleRepository) private readonly roleRepo: IRoleRepository,
        @Inject(IUserRoleRepository) private readonly userRoleRepo: IUserRoleRepository,
        @Inject(IEventBus) private readonly eventBus: IEventBus,
    ) { }

    async importCoreCompany(csvBuffer: Buffer, adminId: number, organizationId: number) {
        const records = await this.fileParser.parseCsvAsync<CoreEmployeeCsvRow>(csvBuffer);
        if (!records.length) return { success: false as const, message: 'File CSV rỗng' };

        // 1. Thu thập dữ liệu duy nhất để xử lý batch
        const uniqueData = this.extractUniqueMetadata(records);
        const defaultPassword = await PasswordUtil.hash('Company@2026');

        return await this.txManager.runInTransaction(async () => {
            // 2. Xử lý Master Data (Locations, Grades, JobTitles) thông qua Repositories
            const locMap = await this.syncLocations(Array.from(uniqueData.locations));
            const gradeMap = await this.syncGrades(Array.from(uniqueData.grades));
            const titleMap = await this.syncJobTitles(Array.from(uniqueData.jobTitles));

            // 3. Xử lý Đơn vị tổ chức (OrgUnits)
            await this.orgRepo.upsertOrgUnits(Array.from(uniqueData.departments.entries()).map(([code, name]) => ({
                organizationId,
                code,
                name: name || code,
                type: code === 'HQ' ? 'COMPANY' : 'DEPARTMENT',
            })));
            const orgsDb = await this.orgRepo.findOrgUnitsByCodes(Array.from(uniqueData.departments.keys()));
            const orgMap = new Map(orgsDb.map(o => [o.code, o.id]));

            let successCount = 0;

            // 4. Xử lý từng nhân sự
            for (const row of records) {
                const orgId = orgMap.get(row.departmentCode);
                const titleId = titleMap.get(row.jobTitle);
                const gradeId = gradeMap.get(Number(row.gradeLevel));

                if (!orgId || !titleId || !gradeId) continue;

                // Xử lý Vị trí (Position)
                const position = await this.getOrCreatePosition(row, orgId, titleId, gradeId);

                // Xử lý Tài khoản (User)
                let user = await this.userRepo.findByUsername(row.username);
                let userId: number;

                if (!user) {
                    const newUser = new User({
                        username: row.username,
                        email: row.email?.trim() || undefined,
                        hashedPassword: defaultPassword,
                        isActive: true,
                    });
                    const savedUser = await this.userRepo.save(newUser);
                    userId = savedUser.id!;

                    // Tạo/Cập nhật Hồ sơ nhân viên (Employee)
                    await this.eventBus.publish(
                        new CoreEmployeeImportedEvent(row.employeeCode, {
                            userId: userId,
                            employeeCode: row.employeeCode,
                            fullName: row.fullName,
                            organizationId: organizationId,
                            positionId: position.id,
                            locationId: locMap.get(row.locationCode) || undefined,
                        })
                    );


                    successCount++;
                } else {
                    userId = user.id!;
                }

                // Gán quyền (Role)
                if (row.role) {
                    const role = await this.roleRepo.findByName(row.role);
                    if (role) {
                        await this.userRoleRepo.save(new UserRole({
                            userId,
                            roleId: role.id!,
                            assignedBy: adminId
                        }));
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

    // --- HÀM TRỢ GIÚP (PRIVATE) ĐỂ GIỮ CODE SẠCH ---

    private extractUniqueMetadata(records: CoreEmployeeCsvRow[]) {
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
        return { locations, departments, jobTitles, grades };
    }

    private async syncLocations(codes: string[]) {
        if (codes.length === 0) return new Map();
        await this.orgRepo.upsertLocations(codes.map(c => ({ code: c, name: c })));
        const locs = await this.orgRepo.findLocationsByCodes(codes);
        return new Map(locs.map(l => [l.code, l.id]));
    }

    private async syncGrades(levels: number[]) {
        if (levels.length === 0) return new Map();
        await this.orgRepo.upsertGrades(levels.map(g => ({ levelNumber: g, code: `BAC_${g}`, name: `Bậc ${g}` })));
        const grades = await this.orgRepo.findGradesByLevels(levels);
        return new Map(grades.map(g => [g.levelNumber, g.id]));
    }

    private async syncJobTitles(names: string[]) {
        if (names.length === 0) return new Map();
        await this.orgRepo.upsertJobTitles(names);
        const titles = await this.orgRepo.findJobTitlesByNames(names);
        return new Map(titles.map(t => [t.name, t.id]));
    }

    private async getOrCreatePosition(row: CoreEmployeeCsvRow, orgId: number, titleId: number, gradeId: number) {
        const posCode = `POS-${row.departmentCode}-${row.gradeLevel}`;
        let position = await this.orgRepo.findPositionByCode(posCode);
        if (!position) {
            position = await this.orgRepo.createPosition({
                code: posCode,
                name: row.positionName || row.jobTitle,
                orgUnitId: orgId,
                jobTitleId: titleId,
                gradeId: gradeId,
                headcountLimit: 10,
            });
        }
        return position;
    }
}
