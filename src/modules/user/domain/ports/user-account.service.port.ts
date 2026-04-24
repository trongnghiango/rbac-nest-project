// src/modules/user/domain/ports/user-account.service.port.ts
import { User } from "../entities/user.entity";

export const IUserAccountService = Symbol('IUserAccountService');

export interface CreateAccountProps {
    username: string;
    email?: string;
    hashedPassword?: string;
    fullName?: string;
    roles?: string[];
}

export interface IUserAccountService {
    /**
     * Khởi tạo tài khoản người dùng mới.
     * Thường dùng cho quy trình Onboarding hoặc Import.
     */
    provisionAccount(props: CreateAccountProps): Promise<User>;

    /**
     * Tìm kiếm user theo username
     */
    findByUsername(username: string): Promise<User | null>;
}
