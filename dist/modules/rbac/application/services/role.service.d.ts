import { Repository } from 'typeorm';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';
export interface AccessControlItem {
    role: string;
    resource: string;
    action: string;
    attributes: string;
}
export declare class RoleService {
    private roleRepository;
    private permissionRepository;
    constructor(roleRepository: Repository<Role>, permissionRepository: Repository<Permission>);
    createRole(data: {
        name: string;
        description?: string;
        isSystem?: boolean;
    }): Promise<Role>;
    assignPermissionToRole(roleId: number, permissionId: number): Promise<void>;
    getRoleWithPermissions(roleName: string): Promise<Role | null>;
    initializeSystemRoles(): Promise<void>;
    initializeSystemPermissions(): Promise<void>;
    getAccessControlList(): Promise<AccessControlItem[]>;
}
