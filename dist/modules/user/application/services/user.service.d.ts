import type { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { User } from '../../domain/entities/user.entity';
export declare class UserService {
    private userRepository;
    constructor(userRepository: IUserRepository);
    createUser(data: {
        id: number;
        username: string;
        email?: string;
        password?: string;
        fullName: string;
    }): Promise<any>;
    validateCredentials(username: string, password: string): Promise<User | null>;
    getUserById(id: number): Promise<ReturnType<User['toJSON']>>;
    updateUserProfile(userId: number, profileData: any): Promise<ReturnType<User['toJSON']>>;
    deactivateUser(userId: number): Promise<void>;
}
