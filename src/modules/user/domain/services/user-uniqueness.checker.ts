import { Injectable, Inject } from '@nestjs/common';
import { IUserRepository } from '../repositories/user.repository';
import { IdentityAlreadyTakenException } from '../exceptions/user-domain.exceptions';

@Injectable()
export class UserUniquenessChecker {
    constructor(
        @Inject(IUserRepository) private readonly userRepository: IUserRepository,
    ) { }

    /**
     * Kiểm tra xem Username hoặc Email đã tồn tại chưa.
     * Nếu tồn tại, ném lỗi Domain Exception ngay lập tức.
     */
    async checkUniqueOrThrow(username: string, email?: string): Promise<void> {
        const identifiers = [username];
        if (email) identifiers.push(email);

        const existing = await this.userRepository.findExistingUsernamesOrEmails(identifiers);

        if (existing.length > 0) {
            // Ưu tiên báo lỗi email nếu cả 2 cùng trùng
            const conflict = existing.find(u => u.email === email) || existing[0];
            const conflictValue = conflict.email === email ? email! : conflict.username;

            throw new IdentityAlreadyTakenException(conflictValue);
        }
    }
}
