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
exports.TestController = void 0;
const common_1 = require("@nestjs/common");
const jwt_auth_guard_1 = require("../../auth/infrastructure/guards/jwt-auth.guard");
const permission_guard_1 = require("../../rbac/infrastructure/guards/permission.guard");
const permission_decorator_1 = require("../../rbac/infrastructure/decorators/permission.decorator");
const public_decorator_1 = require("../../auth/infrastructure/decorators/public.decorator");
const current_user_decorator_1 = require("../../auth/infrastructure/decorators/current-user.decorator");
let TestController = class TestController {
    healthCheck() {
        return {
            status: 'OK',
            timestamp: new Date(),
            service: 'RBAC System',
            version: '1.0.0',
        };
    }
    protectedRoute(user) {
        return {
            message: 'This is a protected route',
            user: {
                id: user.id,
                username: user.username,
                roles: user.roles,
            },
        };
    }
    adminOnly(user) {
        return {
            message: 'This is admin-only route',
            user: {
                id: user.id,
                username: user.username,
            },
        };
    }
    userManagement(user) {
        return {
            message: 'You have user management permission',
            user: {
                id: user.id,
                username: user.username,
            },
        };
    }
};
exports.TestController = TestController;
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.Get)('health'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], TestController.prototype, "healthCheck", null);
__decorate([
    (0, common_1.Get)('protected'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], TestController.prototype, "protectedRoute", null);
__decorate([
    (0, common_1.Get)('admin-only'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard, permission_guard_1.PermissionGuard),
    (0, permission_decorator_1.Permissions)('rbac:manage'),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], TestController.prototype, "adminOnly", null);
__decorate([
    (0, common_1.Get)('user-management'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard, permission_guard_1.PermissionGuard),
    (0, permission_decorator_1.Permissions)('user:manage'),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], TestController.prototype, "userManagement", null);
exports.TestController = TestController = __decorate([
    (0, common_1.Controller)('test')
], TestController);
//# sourceMappingURL=test.controller.js.map