import { AuthenticationService } from '../../application/services/authentication.service';
import { User } from '../../../user/domain/entities/user.entity';
export declare class AuthController {
    private authService;
    constructor(authService: AuthenticationService);
    login(credentials: {
        username: string;
        password: string;
    }): Promise<{
        accessToken: string;
        user: any;
    }>;
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
    getProfile(user: User): {
        user: Omit<User, "hashedPassword" | "updateProfile" | "setPassword" | "deactivate" | "activate" | "toJSON">;
    };
}
