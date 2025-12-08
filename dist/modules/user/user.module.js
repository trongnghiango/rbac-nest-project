"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserModule = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const user_service_1 = require("./application/services/user.service");
const typeorm_user_repository_1 = require("./infrastructure/persistence/typeorm-user.repository");
const user_controller_1 = require("./infrastructure/controllers/user.controller");
const user_entity_1 = require("./domain/entities/user.entity");
let UserModule = class UserModule {
};
exports.UserModule = UserModule;
exports.UserModule = UserModule = __decorate([
    (0, common_1.Module)({
        imports: [typeorm_1.TypeOrmModule.forFeature([user_entity_1.User])],
        controllers: [user_controller_1.UserController],
        providers: [
            user_service_1.UserService,
            {
                provide: 'IUserRepository',
                useClass: typeorm_user_repository_1.TypeOrmUserRepository,
            },
        ],
        exports: [user_service_1.UserService, 'IUserRepository'],
    })
], UserModule);
//# sourceMappingURL=user.module.js.map