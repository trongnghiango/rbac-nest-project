import { Repository } from 'typeorm';
import type { Cache } from 'cache-manager';
import { UserRole } from '../../domain/entities/user-role.entity';
import { Role } from '../../domain/entities/role.entity';
export declare class PermissionService {
    private userRoleRepository;
    private roleRepository;
    private cacheManager;
    private readonly CACHE_TTL;
    private readonly CACHE_PREFIX;
    constructor(userRoleRepository: Repository<UserRole>, roleRepository: Repository<Role>, cacheManager: Cache);
    userHasPermission(userId: number, permissionName: string): Promise<boolean>;
    getUserPermissions(userId: number): Promise<string[]>;
    getUserRoles(userId: number): Promise<string[]>;
    assignRole(userId: number, roleId: number, assignedBy: number): Promise<void>;
    removeRole(userId: number, roleId: number): Promise<void>;
    initializeDefaultData(): void;
}
