import { JwtService } from '@nestjs/jwt';
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import { User } from '../../../user/domain/entities/user.entity';
import { JwtPayload } from '../../../shared/types/common.types';
export declare class AuthenticationService {
    private userRepository;
    private jwtService;
    constructor(userRepository: IUserRepository, jwtService: JwtService);
    login(credentials: {
        username: string;
        password: string;
    }): Promise<{
        accessToken: string;
        user: any;
    }>;
    validateUser(payload: JwtPayload): Promise<ReturnType<User['toJSON']> | null>;
    register(data: {
        id: number;
        username: string;
        password: string;
        email?: string;
        fullName: string;
    }): Promise<{
        accessToken: string;
        user: any;
    }>;
}
