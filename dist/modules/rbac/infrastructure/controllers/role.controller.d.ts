import { RoleService } from '../../application/services/role.service';
import { PermissionService } from '../../application/services/permission.service';
export declare class RoleController {
    private roleService;
    private permissionService;
    constructor(roleService: RoleService, permissionService: PermissionService);
    getAllRoles(): Promise<{
        message: string;
    }>;
    assignRole(body: {
        userId: number;
        roleId: number;
    }): Promise<{
        success: boolean;
        message: string;
    }>;
}
