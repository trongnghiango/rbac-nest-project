import { OnModuleInit } from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from '../../user/domain/entities/user.entity';
import { Role } from '../../rbac/domain/entities/role.entity';
import { Permission } from '../../rbac/domain/entities/permission.entity';
import { UserRole } from '../../rbac/domain/entities/user-role.entity';
export declare class DatabaseSeeder implements OnModuleInit {
    private userRepository;
    private roleRepository;
    private permissionRepository;
    private userRoleRepository;
    constructor(userRepository: Repository<User>, roleRepository: Repository<Role>, permissionRepository: Repository<Permission>, userRoleRepository: Repository<UserRole>);
    onModuleInit(): Promise<void>;
    private seedPermissions;
    private seedRoles;
    private seedUsers;
    private assignRolePermissions;
    private assignUserRoles;
}
