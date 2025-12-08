import { Permission } from './permission.entity';
export declare class Role {
    id: number;
    name: string;
    description: string;
    isActive: boolean;
    isSystem: boolean;
    permissions: Permission[];
    createdAt: Date;
    updatedAt: Date;
    hasPermission(permissionName: string): boolean;
    addPermission(permission: Permission): void;
}
