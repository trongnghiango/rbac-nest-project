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
exports.AuthenticationService = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const password_util_1 = require("../../../shared/utils/password.util");
let AuthenticationService = class AuthenticationService {
    userRepository;
    jwtService;
    constructor(userRepository, jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }
    async login(credentials) {
        const user = await this.userRepository.findByUsername(credentials.username);
        if (!user || !user.isActive) {
            throw new Error('Invalid credentials');
        }
        if (!user.hashedPassword) {
            throw new Error('Password not set for this user');
        }
        const isValid = await password_util_1.PasswordUtil.compare(credentials.password, user.hashedPassword);
        if (!isValid) {
            throw new Error('Invalid credentials');
        }
        const payload = {
            sub: user.id,
            username: user.username,
            roles: [],
        };
        const accessToken = this.jwtService.sign(payload);
        return {
            accessToken,
            user: user.toJSON(),
        };
    }
    async validateUser(payload) {
        const user = await this.userRepository.findById(payload.sub);
        if (!user || !user.isActive) {
            return null;
        }
        return user.toJSON();
    }
    async register(data) {
        const existing = await this.userRepository.findByUsername(data.username);
        if (existing) {
            throw new Error('User already exists');
        }
        const hashedPassword = await password_util_1.PasswordUtil.hash(data.password);
        const user = {
            id: data.id,
            username: data.username,
            email: data.email,
            hashedPassword: hashedPassword,
            fullName: data.fullName,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date(),
        };
        const savedUser = await this.userRepository.save(user);
        const payload = {
            sub: savedUser.id,
            username: savedUser.username,
            roles: [],
        };
        const accessToken = this.jwtService.sign(payload);
        return {
            accessToken,
            user: savedUser.toJSON(),
        };
    }
};
exports.AuthenticationService = AuthenticationService;
exports.AuthenticationService = AuthenticationService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)('IUserRepository')),
    __metadata("design:paramtypes", [Object, jwt_1.JwtService])
], AuthenticationService);
//# sourceMappingURL=authentication.service.js.map