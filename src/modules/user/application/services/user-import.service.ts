import { Injectable, Inject, Logger } from '@nestjs/common';
import { IUserRepository } from '../../domain/repositories/user.repository';
import { IRoleRepository, IUserRoleRepository } from '@modules/rbac/domain/repositories/rbac.repository';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { IFileParser } from '@core/shared/application/ports/file-parser.port';
import { PasswordUtil } from '@core/shared/utils/password.util';
import { User } from '../../domain/entities/user.entity';
import { UserRole } from '@modules/rbac/domain/entities/user-role.entity';

export type UserCsvRow = {
    username: string;
    email: string;
    fullName: string;
    roles: string; // VD: "ADMIN,MANAGER"
    password?: string;
};

@Injectable()
export class UserImportService {
    private readonly logger = new Logger(UserImportService.name);

    constructor(
        @Inject(IUserRepository) private userRepo: IUserRepository,
        @Inject(IRoleRepository) private roleRepo: IRoleRepository,
        @Inject(IUserRoleRepository) private userRoleRepo: IUserRoleRepository,
        @Inject(ITransactionManager) private txManager: ITransactionManager,
        @Inject(IFileParser) private fileParser: IFileParser,
    ) { }

    async importFromCsv(csvBuffer: Buffer, adminId: number) {
        // 1. Parse CSV
        const records = await this.fileParser.parseCsvAsync<UserCsvRow>(csvBuffer);
        if (!records.length) return { success: false, message: 'File rỗng' };

        const errors: string[] = [];
        const validRows: UserCsvRow[] = [];

        // 2. Thu thập dữ liệu để check 1 lần duy nhất (O(1) thay vì O(N))
        const usernamesToCheck = [...new Set(records.map(r => r.username).filter(Boolean))];
        const emailsToCheck = [...new Set(records.map(r => r.email).filter(Boolean))];
        const allRolesSet = new Set<string>();

        records.forEach(r => {
            if (r.roles) {
                r.roles.split(',').forEach(role => allRolesSet.add(role.trim().toUpperCase()));
            }
        });

        // 3. Query DB 1 lần lấy dữ liệu đối chiếu
        const existingUsers = await this.userRepo.findExistingUsernamesOrEmails([...usernamesToCheck, ...emailsToCheck]);
        const existingUsernames = new Set(existingUsers.map(u => u.username));
        const existingEmails = new Set(existingUsers.map(u => u.email));

        const validDbRoles = await this.roleRepo.findInNames(Array.from(allRolesSet));
        const roleMap = new Map(validDbRoles.map(r => [r.name.toUpperCase(), r.id]));

        // 4. Validate từng dòng trên RAM
        records.forEach((row, index) => {
            const line = index + 2; // Dòng 1 là header
            if (!row.username || !row.fullName) {
                errors.push(`Dòng ${line}: Thiếu username hoặc fullName.`);
                return;
            }
            if (existingUsernames.has(row.username)) {
                errors.push(`Dòng ${line}: Username '${row.username}' đã tồn tại.`);
                return;
            }
            if (row.email && existingEmails.has(row.email)) {
                errors.push(`Dòng ${line}: Email '${row.email}' đã tồn tại.`);
                return;
            }
            validRows.push(row);
        });

        if (validRows.length === 0) {
            return { success: false, message: 'Không có dữ liệu hợp lệ để import', errors, stats: { total: records.length, success: 0, failed: errors.length } };
        }

        // 5. Chunk Hashing Password (Chống treo Node.js)
        const usersToInsert: User[] = [];
        const chunkSize = 50;

        for (let i = 0; i < validRows.length; i += chunkSize) {
            const chunk = validRows.slice(i, i + chunkSize);

            // Xử lý song song 50 passwords cùng lúc
            const hashedPasswords = await Promise.all(
                chunk.map(row => PasswordUtil.hash(row.password || 'Hrm@2026'))
            );

            chunk.forEach((row, j) => {
                usersToInsert.push(new User(
                    undefined as any,
                    row.username,
                    row.email || undefined,
                    hashedPasswords[j],
                    row.fullName,
                    true,
                    [], undefined, undefined, undefined, undefined, new Date(), new Date()
                ));
            });
        }

        // 6. Thực thi Transaction Bulk Insert
        await this.txManager.runInTransaction(async (tx) => {
            // 6.1 Insert toàn bộ User (Và lấy ID trả về)
            const insertedUsers = await this.userRepo.saveMany(usersToInsert, tx);

            // 6.2 Chuẩn bị data cho bảng UserRoles
            const userRolesToInsert: UserRole[] = [];

            insertedUsers.forEach((savedUser) => {
                // Tìm lại dòng CSV gốc dựa vào username
                const originalRow = validRows.find(r => r.username === savedUser.username);
                if (originalRow && originalRow.roles && savedUser.id) {
                    const roleNames = originalRow.roles.split(',').map(r => r.trim().toUpperCase());
                    roleNames.forEach(rName => {
                        const roleId = roleMap.get(rName);
                        if (roleId) {
                            userRolesToInsert.push(new UserRole(
                                savedUser.id!,
                                roleId!,
                                adminId, // Người thực hiện import
                                undefined,
                                new Date()
                            ));
                        }
                    });
                }
            });

            // 6.3 Insert toàn bộ UserRoles
            if (userRolesToInsert.length > 0) {
                await this.userRoleRepo.saveMany(userRolesToInsert, tx);
            }
        });

        return {
            success: true,
            message: 'Import Users hoàn tất',
            stats: {
                totalProcessed: records.length,
                successCount: validRows.length,
                failedCount: errors.length
            },
            errors
        };
    }
}
