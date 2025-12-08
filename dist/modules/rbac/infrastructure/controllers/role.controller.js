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
exports.RoleController = void 0;
const common_1 = require("@nestjs/common");
const role_service_1 = require("../../application/services/role.service");
const permission_service_1 = require("../../application/services/permission.service");
const jwt_auth_guard_1 = require("../../../auth/infrastructure/guards/jwt-auth.guard");
const permission_decorator_1 = require("../decorators/permission.decorator");
let RoleController = class RoleController {
    roleService;
    permissionService;
    constructor(roleService, permissionService) {
        this.roleService = roleService;
        this.permissionService = permissionService;
    }
    async getAllRoles() {
        return { message: 'Get all roles' };
    }
    async assignRole(body) {
        await this.permissionService.assignRole(body.userId, body.roleId, 1);
        return { success: true, message: 'Role assigned' };
    }
};
exports.RoleController = RoleController;
__decorate([
    (0, common_1.Get)(),
    (0, permission_decorator_1.Permissions)('rbac:manage'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], RoleController.prototype, "getAllRoles", null);
__decorate([
    (0, common_1.Post)('assign'),
    (0, permission_decorator_1.Permissions)('rbac:manage'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], RoleController.prototype, "assignRole", null);
exports.RoleController = RoleController = __decorate([
    (0, common_1.Controller)('rbac/roles'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    __metadata("design:paramtypes", [role_service_1.RoleService,
        permission_service_1.PermissionService])
], RoleController);
//# sourceMappingURL=role.controller.js.map