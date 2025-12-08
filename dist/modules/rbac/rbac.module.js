"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RbacModule = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const cache_manager_1 = require("@nestjs/cache-manager");
const config_1 = require("@nestjs/config");
const user_module_1 = require("../user/user.module");
const permission_service_1 = require("./application/services/permission.service");
const role_service_1 = require("./application/services/role.service");
const permission_guard_1 = require("./infrastructure/guards/permission.guard");
const role_controller_1 = require("./infrastructure/controllers/role.controller");
const role_entity_1 = require("./domain/entities/role.entity");
const permission_entity_1 = require("./domain/entities/permission.entity");
const user_role_entity_1 = require("./domain/entities/user-role.entity");
let RbacModule = class RbacModule {
};
exports.RbacModule = RbacModule;
exports.RbacModule = RbacModule = __decorate([
    (0, common_1.Module)({
        imports: [
            user_module_1.UserModule,
            typeorm_1.TypeOrmModule.forFeature([role_entity_1.Role, permission_entity_1.Permission, user_role_entity_1.UserRole]),
            cache_manager_1.CacheModule.registerAsync({
                imports: [config_1.ConfigModule],
                useFactory: (configService) => ({
                    ttl: configService.get('RBAC_CACHE_TTL', 300),
                    max: configService.get('RBAC_CACHE_MAX', 1000),
                }),
                inject: [config_1.ConfigService],
            }),
        ],
        controllers: [role_controller_1.RoleController],
        providers: [permission_service_1.PermissionService, role_service_1.RoleService, permission_guard_1.PermissionGuard],
        exports: [permission_service_1.PermissionService, permission_guard_1.PermissionGuard, role_service_1.RoleService],
    })
], RbacModule);
//# sourceMappingURL=rbac.module.js.map