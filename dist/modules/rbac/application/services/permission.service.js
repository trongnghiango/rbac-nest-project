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
exports.PermissionService = void 0;
const common_1 = require("@nestjs/common");
const cache_manager_1 = require("@nestjs/cache-manager");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const user_role_entity_1 = require("../../domain/entities/user-role.entity");
const role_entity_1 = require("../../domain/entities/role.entity");
let PermissionService = class PermissionService {
    userRoleRepository;
    roleRepository;
    cacheManager;
    CACHE_TTL = 300;
    CACHE_PREFIX = 'rbac:permissions:';
    constructor(userRoleRepository, roleRepository, cacheManager) {
        this.userRoleRepository = userRoleRepository;
        this.roleRepository = roleRepository;
        this.cacheManager = cacheManager;
    }
    async userHasPermission(userId, permissionName) {
        const cacheKey = `${this.CACHE_PREFIX}${userId}`;
        const cached = await this.cacheManager.get(cacheKey);
        if (cached) {
            return cached.includes(permissionName) || cached.includes('*');
        }
        const userRoles = await this.userRoleRepository.find({
            where: { userId },
            relations: ['role'],
        });
        const activeRoles = userRoles.filter((ur) => ur.isActive() && ur.role.isActive);
        const roleIds = activeRoles.map((ur) => ur.roleId);
        if (roleIds.length === 0)
            return false;
        const roles = await this.roleRepository.find({
            where: { id: (0, typeorm_2.In)(roleIds), isActive: true },
            relations: ['permissions'],
        });
        const permissions = new Set();
        for (const role of roles) {
            if (role?.permissions) {
                role.permissions.forEach((p) => {
                    if (p.isActive) {
                        permissions.add(p.name);
                    }
                });
            }
        }
        const permissionArray = Array.from(permissions);
        await this.cacheManager.set(cacheKey, permissionArray, this.CACHE_TTL);
        return permissionArray.includes(permissionName);
    }
    async getUserPermissions(userId) {
        const cacheKey = `${this.CACHE_PREFIX}${userId}`;
        const cached = await this.cacheManager.get(cacheKey);
        if (cached)
            return cached;
        const userRoles = await this.userRoleRepository.find({
            where: { userId },
            relations: ['role'],
        });
        const activeRoles = userRoles.filter((ur) => ur.isActive());
        const roleIds = activeRoles.map((ur) => ur.roleId);
        if (roleIds.length === 0)
            return [];
        const roles = await this.roleRepository.find({
            where: {
                id: (0, typeorm_2.In)(roleIds),
                isActive: true,
            },
            relations: ['permissions'],
        });
        const permissions = new Set();
        for (const role of roles) {
            if (role?.permissions) {
                role.permissions.forEach((p) => {
                    if (p.isActive) {
                        permissions.add(p.name);
                    }
                });
            }
        }
        const permissionArray = Array.from(permissions);
        await this.cacheManager.set(cacheKey, permissionArray, this.CACHE_TTL);
        return permissionArray;
    }
    async getUserRoles(userId) {
        const userRoles = await this.userRoleRepository.find({
            where: { userId },
            relations: ['role'],
        });
        const activeRoles = userRoles.filter((ur) => ur.isActive());
        return activeRoles.map((ur) => ur.role.name);
    }
    async assignRole(userId, roleId, assignedBy) {
        const existing = await this.userRoleRepository.findOne({
            where: { userId, roleId },
        });
        if (existing) {
            throw new Error('User already has this role');
        }
        await this.userRoleRepository.save({
            userId,
            roleId,
            assignedBy,
            assignedAt: new Date(),
        });
        await this.cacheManager.del(`${this.CACHE_PREFIX}${userId}`);
    }
    async removeRole(userId, roleId) {
        await this.userRoleRepository.delete({ userId, roleId });
        await this.cacheManager.del(`${this.CACHE_PREFIX}${userId}`);
    }
    initializeDefaultData() {
        console.log('Initializing default RBAC data...');
    }
};
exports.PermissionService = PermissionService;
exports.PermissionService = PermissionService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(user_role_entity_1.UserRole)),
    __param(1, (0, typeorm_1.InjectRepository)(role_entity_1.Role)),
    __param(2, (0, common_1.Inject)(cache_manager_1.CACHE_MANAGER)),
    __metadata("design:paramtypes", [typeorm_2.Repository,
        typeorm_2.Repository, Object])
], PermissionService);
//# sourceMappingURL=permission.service.js.map