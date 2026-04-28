// src/modules/user/application/services/user-account.service.ts
import { Injectable, Inject, InternalServerErrorException, Logger } from '@nestjs/common';
import { IUserAccountService, CreateAccountProps } from '../../domain/ports/user-account.service.port';
import { IUserRepository } from '../../domain/repositories/user.repository';
import { User } from '../../domain/entities/user.entity';
import { UserUniquenessChecker } from '../../domain/services/user-uniqueness.checker';
import { AUDIT_LOG_PORT, IAuditLogService } from '@core/shared/application/ports/audit-log.port';

@Injectable()
export class UserAccountService implements IUserAccountService {
    private readonly logger = new Logger(UserAccountService.name);

    constructor(
        @Inject(IUserRepository) private readonly userRepository: IUserRepository,
        private readonly uniquenessChecker: UserUniquenessChecker,
        @Inject(AUDIT_LOG_PORT) private readonly auditLog: IAuditLogService,
    ) { }

    async provisionAccount(props: CreateAccountProps): Promise<User> {
        // 1. Kiểm tra tính duy nhất (Username/Email)
        await this.uniquenessChecker.checkUniqueOrThrow(props.username, props.email);

        // 2. Khởi tạo Entity
        const newUser = new User({
            username: props.username,
            email: props.email,
            hashedPassword: props.hashedPassword,
            personalInfo: {
                fullName: props.fullName
            },
            isActive: true,
            roles: props.roles || [],
        });

        // 3. Lưu (Transaction sẽ được quản lý bởi Orchestrator Service gọi hàm này)
        const savedUser = await this.userRepository.save(newUser);
        if (!savedUser.id) {
            throw new InternalServerErrorException('Failed to generate User ID during provision');
        }

        // ✅ Ghi Audit Log khi tạo User mới (Fire-and-forget)
        try {
            this.auditLog.log({
                action: 'USER.PROVISIONED',
                resource: 'users',
                resourceId: savedUser.id.toString(),
                actorId: 'SYSTEM',
                actorName: 'SYSTEM (USER_PROVISION)',
                metadata: { username: savedUser.username, email: savedUser.email, roles: props.roles },
                severity: 'INFO'
            });
        } catch (error) {
            this.logger.error(`[Audit Log] Lỗi khi ghi nhận Audit USER.PROVISIONED: ${error.message}`);
        }

        return savedUser;
    }

    async findByUsername(username: string): Promise<User | null> {
        return this.userRepository.findByUsername(username);
    }
}
