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
exports.UserRole = void 0;
const typeorm_1 = require("typeorm");
const role_entity_1 = require("./role.entity");
let UserRole = class UserRole {
    userId;
    roleId;
    assignedBy;
    expiresAt;
    assignedAt;
    role;
    isActive() {
        if (!this.expiresAt)
            return true;
        return new Date() < this.expiresAt;
    }
};
exports.UserRole = UserRole;
__decorate([
    (0, typeorm_1.PrimaryColumn)('bigint'),
    __metadata("design:type", Number)
], UserRole.prototype, "userId", void 0);
__decorate([
    (0, typeorm_1.PrimaryColumn)('int'),
    __metadata("design:type", Number)
], UserRole.prototype, "roleId", void 0);
__decorate([
    (0, typeorm_1.Column)('bigint', { nullable: true }),
    __metadata("design:type", Number)
], UserRole.prototype, "assignedBy", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'timestamptz', nullable: true }),
    __metadata("design:type", Date)
], UserRole.prototype, "expiresAt", void 0);
__decorate([
    (0, typeorm_1.CreateDateColumn)(),
    __metadata("design:type", Date)
], UserRole.prototype, "assignedAt", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => role_entity_1.Role),
    (0, typeorm_1.JoinColumn)({ name: 'roleId' }),
    __metadata("design:type", role_entity_1.Role)
], UserRole.prototype, "role", void 0);
exports.UserRole = UserRole = __decorate([
    (0, typeorm_1.Entity)('user_roles'),
    (0, typeorm_1.Index)('idx_user_roles_user_id', ['userId']),
    (0, typeorm_1.Index)('idx_user_roles_role_id', ['roleId'])
], UserRole);
//# sourceMappingURL=user-role.entity.js.map