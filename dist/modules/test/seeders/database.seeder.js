"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DatabaseSeeder = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const bcrypt = __importStar(require("bcrypt"));
const user_entity_1 = require("../../user/domain/entities/user.entity");
const role_entity_1 = require("../../rbac/domain/entities/role.entity");
const permission_entity_1 = require("../../rbac/domain/entities/permission.entity");
const user_role_entity_1 = require("../../rbac/domain/entities/user-role.entity");
const rbac_constants_1 = require("../../rbac/domain/constants/rbac.constants");
let DatabaseSeeder = class DatabaseSeeder {
    userRepository;
    roleRepository;
    permissionRepository;
    userRoleRepository;
    constructor(userRepository, roleRepository, permissionRepository, userRoleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.userRoleRepository = userRoleRepository;
    }
    async onModuleInit() {
        if (process.env.NODE_ENV !== 'development') {
            return;
        }
        console.log('Seeding database...');
        await this.seedPermissions();
        await this.seedRoles();
        await this.seedUsers();
        await this.assignRolePermissions();
        await this.assignUserRoles();
        console.log('Database seeded successfully!');
    }
    async seedPermissions() {
        const permissions = Object.values(rbac_constants_1.SystemPermission).map((name) => {
            const [resource, action] = name.split(':');
            return this.permissionRepository.create({
                name,
                description: `System permission: ${name}`,
                resourceType: resource,
                action: action,
                isActive: true,
                createdAt: new Date(),
            });
        });
        for (const p of permissions) {
            const exists = await this.permissionRepository.findOne({
                where: { name: p.name },
            });
            if (!exists) {
                await this.permissionRepository.save(p);
            }
        }
        console.log(`Checked permissions`);
    }
    async seedRoles() {
        const roles = Object.values(rbac_constants_1.SystemRole).map((name) => ({
            name,
            description: `System role: ${name}`,
            isSystem: true,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date(),
        }));
        for (const r of roles) {
            const exists = await this.roleRepository.findOne({
                where: { name: r.name },
            });
            if (!exists) {
                await this.roleRepository.save(r);
            }
        }
        console.log(`Checked roles`);
    }
    async seedUsers() {
        const users = [
            {
                id: 1001,
                username: 'superadmin',
                email: 'superadmin@example.com',
                hashedPassword: await bcrypt.hash('SuperAdmin123!', 10),
                fullName: 'Super Administrator',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date(),
            },
            {
                id: 1002,
                username: 'admin',
                email: 'admin@example.com',
                hashedPassword: await bcrypt.hash('Admin123!', 10),
                fullName: 'Administrator',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date(),
            },
            {
                id: 1003,
                username: 'manager',
                email: 'manager@example.com',
                hashedPassword: await bcrypt.hash('Manager123!', 10),
                fullName: 'Manager User',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date(),
            },
            {
                id: 1004,
                username: 'staff',
                email: 'staff@example.com',
                hashedPassword: await bcrypt.hash('Staff123!', 10),
                fullName: 'Staff User',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date(),
            },
            {
                id: 1005,
                username: 'user1',
                email: 'user1@example.com',
                hashedPassword: await bcrypt.hash('User123!', 10),
                fullName: 'Regular User 1',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date(),
            },
            {
                id: 1006,
                username: 'user2',
                email: 'user2@example.com',
                hashedPassword: await bcrypt.hash('User123!', 10),
                fullName: 'Regular User 2',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date(),
            },
        ];
        for (const u of users) {
            const exists = await this.userRepository.findOne({
                where: { username: u.username },
            });
            if (!exists) {
                await this.userRepository.save(u);
            }
        }
        console.log(`Checked users`);
    }
    async assignRolePermissions() {
        const permissions = await this.permissionRepository.find();
        const roles = await this.roleRepository.find({
            relations: ['permissions'],
        });
        const roleMap = new Map(roles.map((r) => [r.name, r]));
        const superAdmin = roleMap.get(rbac_constants_1.SystemRole.SUPER_ADMIN);
        if (superAdmin) {
            superAdmin.permissions = permissions;
            await this.roleRepository.save(superAdmin);
        }
        const admin = roleMap.get(rbac_constants_1.SystemRole.ADMIN);
        if (admin) {
            admin.permissions = permissions.filter((p) => !p.name.includes('system:'));
            await this.roleRepository.save(admin);
        }
        const manager = roleMap.get(rbac_constants_1.SystemRole.MANAGER);
        if (manager) {
            const managerPermissions = permissions.filter((p) => p.name.includes('report:') ||
                p.name.includes('booking:manage') ||
                p.name.includes('user:read'));
            manager.permissions = managerPermissions;
            await this.roleRepository.save(manager);
        }
        const staff = roleMap.get(rbac_constants_1.SystemRole.STAFF);
        if (staff) {
            const staffPermissions = permissions.filter((p) => p.name.includes('booking:create') ||
                p.name.includes('booking:read') ||
                p.name.includes('booking:update') ||
                p.name.includes('payment:process'));
            staff.permissions = staffPermissions;
            await this.roleRepository.save(staff);
        }
        const userRole = roleMap.get(rbac_constants_1.SystemRole.USER);
        if (userRole) {
            userRole.permissions = permissions.filter((p) => p.name === rbac_constants_1.SystemPermission.USER_READ ||
                p.name === rbac_constants_1.SystemPermission.BOOKING_CREATE ||
                p.name === rbac_constants_1.SystemPermission.BOOKING_READ ||
                p.name === rbac_constants_1.SystemPermission.PAYMENT_PROCESS);
            await this.roleRepository.save(userRole);
        }
        console.log('Assigned permissions to roles');
    }
    async assignUserRoles() {
        const roles = await this.roleRepository.find();
        const roleMap = new Map(roles.map((r) => [r.name, r.id]));
        const assignments = [
            { userId: 1001, roleName: rbac_constants_1.SystemRole.SUPER_ADMIN },
            { userId: 1002, roleName: rbac_constants_1.SystemRole.ADMIN },
            { userId: 1003, roleName: rbac_constants_1.SystemRole.MANAGER },
            { userId: 1004, roleName: rbac_constants_1.SystemRole.STAFF },
            { userId: 1005, roleName: rbac_constants_1.SystemRole.USER },
            { userId: 1006, roleName: rbac_constants_1.SystemRole.USER },
        ];
        for (const assignment of assignments) {
            const roleId = roleMap.get(assignment.roleName);
            if (roleId) {
                const exists = await this.userRoleRepository.findOne({
                    where: { userId: assignment.userId, roleId },
                });
                if (!exists) {
                    await this.userRoleRepository.save({
                        userId: assignment.userId,
                        roleId,
                        assignedBy: 1001,
                        assignedAt: new Date(),
                    });
                }
            }
        }
        console.log('Assigned roles to users');
    }
};
exports.DatabaseSeeder = DatabaseSeeder;
exports.DatabaseSeeder = DatabaseSeeder = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __param(1, (0, typeorm_1.InjectRepository)(role_entity_1.Role)),
    __param(2, (0, typeorm_1.InjectRepository)(permission_entity_1.Permission)),
    __param(3, (0, typeorm_1.InjectRepository)(user_role_entity_1.UserRole)),
    __metadata("design:paramtypes", [typeorm_2.Repository,
        typeorm_2.Repository,
        typeorm_2.Repository,
        typeorm_2.Repository])
], DatabaseSeeder);
//# sourceMappingURL=database.seeder.js.map