// src/modules/user/application/services/user-account.service.ts
import { Injectable, Inject, InternalServerErrorException } from '@nestjs/common';
import { IUserAccountService, CreateAccountProps } from '../../domain/ports/user-account.service.port';
import { IUserRepository } from '../../domain/repositories/user.repository';
import { User } from '../../domain/entities/user.entity';
import { UserUniquenessChecker } from '../../domain/services/user-uniqueness.checker';

@Injectable()
export class UserAccountService implements IUserAccountService {
    constructor(
        @Inject(IUserRepository) private readonly userRepository: IUserRepository,
        private readonly uniquenessChecker: UserUniquenessChecker,
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

        return savedUser;
    }

    async findByUsername(username: string): Promise<User | null> {
        return this.userRepository.findByUsername(username);
    }
}
