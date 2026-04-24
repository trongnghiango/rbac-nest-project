// src/modules/rbac/domain/ports/rbac-manage.service.port.ts
export const IRbacManageService = Symbol('IRbacManageService');

export interface IRbacManageService {
    /**
     * Gán role cho user.
     * Thường dùng khi onboard nhân viên mới.
     */
    assignRoleToUser(userId: number, roleName: string, assignedBy: number): Promise<void>;

    /**
     * Tìm role theo tên (để validation)
     */
    findRoleByName(name: string): Promise<any>;
}
