// src/modules/rbac/application/services/rbac-manage.service.ts
import { Injectable, Inject, NotFoundException } from '@nestjs/common';
import { IRbacManageService } from '../../domain/ports/rbac-manage.service.port';
import { IRoleRepository, IUserRoleRepository } from '../../domain/repositories/rbac.repository';
import { UserRole } from '../../domain/entities/user-role.entity';
import { AUDIT_LOG_PORT, IAuditLogService } from '@core/shared/application/ports/audit-log.port';

@Injectable()
export class RbacManageService implements IRbacManageService {
    constructor(
        @Inject(IRoleRepository) private readonly roleRepo: IRoleRepository,
        @Inject(IUserRoleRepository) private readonly userRoleRepo: IUserRoleRepository,
        @Inject(AUDIT_LOG_PORT) private readonly auditLog: IAuditLogService,
    ) { }

    async assignRoleToUser(userId: number, roleName: string, assignedBy: number): Promise<void> {
        const role = await this.roleRepo.findByName(roleName);
        if (!role) {
            throw new NotFoundException(`Role ${roleName} not found`);
        }

        const userRole = new UserRole({
            userId,
            roleId: role.id!,
            assignedBy,
        });

        await this.userRoleRepo.save(userRole);

        // ✅ Ghi Audit Log cho hành động nhạy cảm
        this.auditLog.log({
            action: 'RBAC.ROLE_ASSIGNED',
            resource: 'users',
            resource_id: userId.toString(),
            actor_id: assignedBy,
            metadata: { roleName, roleId: role.id },
            severity: 'WARN' // Role assignment là hành động quan trọng
        });
    }

    async findRoleByName(name: string): Promise<any> {
        return this.roleRepo.findByName(name);
    }
}
