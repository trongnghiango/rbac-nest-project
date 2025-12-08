import { Role } from './role.entity';
export declare class UserRole {
    userId: number;
    roleId: number;
    assignedBy: number;
    expiresAt: Date;
    assignedAt: Date;
    role: Role;
    isActive(): boolean;
}
