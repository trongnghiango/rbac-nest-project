"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RoleService = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const rbac_constants_1 = require("../../domain/constants/rbac.constants");
const role_entity_1 = require("../../domain/entities/role.entity");
const permission_entity_1 = require("../../domain/entities/permission.entity");
let RoleService = class RoleService {
    roleRepository;
    permissionRepository;
    constructor(roleRepository, permissionRepository) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
    }
    async createRole(data) {
        const existing = await this.roleRepository.findOne({
            where: { name: data.name },
        });
        if (existing) {
            throw new Error(`Role ${data.name} already exists`);
        }
        const role = this.roleRepository.create({
            name: data.name,
            description: data.description,
            isSystem: data.isSystem || false,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date(),
        });
        return this.roleRepository.save(role);
    }
    async assignPermissionToRole(roleId, permissionId) {
        const role = await this.roleRepository.findOne({
            where: { id: roleId },
            relations: ['permissions'],
        });
        if (!role) {
            throw new Error('Role not found');
        }
        const permission = await this.permissionRepository.findOne({
            where: { id: permissionId },
        });
        if (!permission) {
            throw new Error('Permission not found');
        }
        if (!role.permissions)
            role.permissions = [];
        const alreadyHas = role.permissions.some((p) => p.id === permissionId);
        if (!alreadyHas) {
            role.permissions.push(permission);
            role.updatedAt = new Date();
            await this.roleRepository.save(role);
        }
    }
    async getRoleWithPermissions(roleName) {
        return this.roleRepository.findOne({
            where: { name: roleName },
            relations: ['permissions'],
        });
    }
    async initializeSystemRoles() {
        const systemRoles = Object.values(rbac_constants_1.SystemRole);
        for (const roleName of systemRoles) {
            const existing = await this.roleRepository.findOne({
                where: { name: roleName },
            });
            if (!existing) {
                await this.createRole({
                    name: roleName,
                    description: `System role: ${roleName}`,
                    isSystem: true,
                });
            }
        }
    }
    async initializeSystemPermissions() {
        const systemPermissions = Object.values(rbac_constants_1.SystemPermission);
        for (const permName of systemPermissions) {
            const existing = await this.permissionRepository.findOne({
                where: { name: permName },
            });
            if (!existing) {
                const [resource, action] = permName.split(':');
                await this.permissionRepository.save({
                    name: permName,
                    description: `Permission: ${permName}`,
                    resourceType: resource,
                    action: action,
                    isActive: true,
                    createdAt: new Date(),
                });
            }
        }
    }
    async getAccessControlList() {
        const roles = await this.roleRepository.find({
            relations: ['permissions'],
            where: { isActive: true },
        });
        const accessControlList = [];
        roles.forEach((role) => {
            if (role.permissions) {
                role.permissions.forEach((permission) => {
                    let attributes = '*';
                    if (role.name === 'USER' && permission.resourceType === 'video') {
                        attributes = '*, !views';
                    }
                    accessControlList.push({
                        role: role.name.toLowerCase(),
                        resource: permission.resourceType || 'all',
                        action: permission.action || 'manage',
                        attributes: attributes,
                    });
                });
            }
        });
        return accessControlList;
    }
};
exports.RoleService = RoleService;
exports.RoleService = RoleService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(role_entity_1.Role)),
    __param(1, (0, typeorm_1.InjectRepository)(permission_entity_1.Permission)),
    __metadata("design:paramtypes", [typeorm_2.Repository,
        typeorm_2.Repository])
], RoleService);
//# sourceMappingURL=role.service.js.map