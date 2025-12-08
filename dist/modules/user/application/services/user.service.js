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
exports.UserService = void 0;
const common_1 = require("@nestjs/common");
const password_util_1 = require("../../../shared/utils/password.util");
const user_entity_1 = require("../../domain/entities/user.entity");
let UserService = class UserService {
    userRepository;
    constructor(userRepository) {
        this.userRepository = userRepository;
    }
    async createUser(data) {
        const existing = await this.userRepository.findByUsername(data.username);
        if (existing) {
            throw new Error('User already exists');
        }
        let hashedPassword;
        if (data.password) {
            if (!password_util_1.PasswordUtil.validateStrength(data.password)) {
                throw new Error('Password does not meet strength requirements');
            }
            hashedPassword = await password_util_1.PasswordUtil.hash(data.password);
        }
        const newUser = new user_entity_1.User();
        newUser.id = data.id;
        newUser.username = data.username;
        newUser.email = data.email;
        newUser.hashedPassword = hashedPassword;
        newUser.fullName = data.fullName;
        newUser.isActive = true;
        newUser.createdAt = new Date();
        newUser.updatedAt = new Date();
        const user = await this.userRepository.save(newUser);
        return user.toJSON();
    }
    async validateCredentials(username, password) {
        const user = await this.userRepository.findByUsername(username);
        if (!user || !user.isActive || !user.hashedPassword) {
            return null;
        }
        const isValid = await password_util_1.PasswordUtil.compare(password, user.hashedPassword);
        return isValid ? user : null;
    }
    async getUserById(id) {
        const user = await this.userRepository.findById(id);
        if (!user) {
            throw new Error('User not found');
        }
        return user.toJSON();
    }
    async updateUserProfile(userId, profileData) {
        const user = await this.userRepository.findById(userId);
        if (!user) {
            throw new Error('User not found');
        }
        user.updateProfile(profileData);
        const updated = await this.userRepository.save(user);
        return updated.toJSON();
    }
    async deactivateUser(userId) {
        const user = await this.userRepository.findById(userId);
        if (!user) {
            throw new Error('User not found');
        }
        user.deactivate();
        await this.userRepository.save(user);
    }
};
exports.UserService = UserService;
exports.UserService = UserService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)('IUserRepository')),
    __metadata("design:paramtypes", [Object])
], UserService);
//# sourceMappingURL=user.service.js.map