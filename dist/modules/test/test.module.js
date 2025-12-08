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
Object.defineProperty(exports, "__esModule", { value: true });
exports.TestModule = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const user_module_1 = require("../user/user.module");
const rbac_module_1 = require("../rbac/rbac.module");
const database_seeder_1 = require("./seeders/database.seeder");
const test_controller_1 = require("./controllers/test.controller");
const user_entity_1 = require("../user/domain/entities/user.entity");
const role_entity_1 = require("../rbac/domain/entities/role.entity");
const permission_entity_1 = require("../rbac/domain/entities/permission.entity");
const user_role_entity_1 = require("../rbac/domain/entities/user-role.entity");
let TestModule = class TestModule {
    databaseSeeder;
    constructor(databaseSeeder) {
        this.databaseSeeder = databaseSeeder;
    }
    async onModuleInit() {
        await this.databaseSeeder.onModuleInit();
    }
};
exports.TestModule = TestModule;
exports.TestModule = TestModule = __decorate([
    (0, common_1.Module)({
        imports: [
            user_module_1.UserModule,
            rbac_module_1.RbacModule,
            typeorm_1.TypeOrmModule.forFeature([user_entity_1.User, role_entity_1.Role, permission_entity_1.Permission, user_role_entity_1.UserRole]),
        ],
        controllers: [test_controller_1.TestController],
        providers: [database_seeder_1.DatabaseSeeder],
    }),
    __metadata("design:paramtypes", [database_seeder_1.DatabaseSeeder])
], TestModule);
//# sourceMappingURL=test.module.js.map