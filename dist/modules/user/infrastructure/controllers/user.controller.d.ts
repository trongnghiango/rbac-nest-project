import { UserService } from '../../application/services/user.service';
import { User } from '../../domain/entities/user.entity';
export declare class UserController {
    private userService;
    constructor(userService: UserService);
    getProfile(user: User): Promise<Omit<User, "hashedPassword" | "updateProfile" | "setPassword" | "deactivate" | "activate" | "toJSON">>;
    updateProfile(user: User, profileData: any): Promise<Omit<User, "hashedPassword" | "updateProfile" | "setPassword" | "deactivate" | "activate" | "toJSON">>;
    getUserById(id: number): Promise<Omit<User, "hashedPassword" | "updateProfile" | "setPassword" | "deactivate" | "activate" | "toJSON">>;
}
