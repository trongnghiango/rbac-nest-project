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
exports.TypeOrmUserRepository = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("typeorm");
const typeorm_2 = require("@nestjs/typeorm");
const user_entity_1 = require("../../domain/entities/user.entity");
const user_entity_2 = require("../../domain/entities/user.entity");
let TypeOrmUserRepository = class TypeOrmUserRepository {
    repository;
    constructor(repository) {
        this.repository = repository;
    }
    async findById(id) {
        const entity = await this.repository.findOne({ where: { id } });
        return entity ? this.toDomain(entity) : null;
    }
    async findByUsername(username) {
        const entity = await this.repository.findOne({ where: { username } });
        return entity ? this.toDomain(entity) : null;
    }
    async findByEmail(email) {
        const entity = await this.repository.findOne({ where: { email } });
        return entity ? this.toDomain(entity) : null;
    }
    async findAllActive() {
        const entities = await this.repository.find({
            where: { isActive: true },
            order: { createdAt: 'DESC' },
        });
        return entities.map((entity) => this.toDomain(entity));
    }
    async save(user) {
        const entity = this.toPersistence(user);
        const saved = await this.repository.save(entity);
        return this.toDomain(saved);
    }
    async update(id, data) {
        await this.repository.update(id, this.toPersistence(data));
        const updated = await this.repository.findOne({ where: { id } });
        return this.toDomain(updated);
    }
    async delete(id) {
        await this.repository.delete(id);
    }
    async count() {
        return this.repository.count();
    }
    toDomain(entity) {
        const user = new user_entity_1.User();
        Object.assign(user, entity);
        return user;
    }
    toPersistence(domain) {
        const { id, username, email, hashedPassword, fullName, isActive, profile, createdAt, updatedAt, } = domain;
        return {
            id,
            username,
            email,
            hashedPassword,
            fullName,
            isActive,
            profile,
            createdAt,
            updatedAt,
        };
    }
};
exports.TypeOrmUserRepository = TypeOrmUserRepository;
exports.TypeOrmUserRepository = TypeOrmUserRepository = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_2.InjectRepository)(user_entity_2.User)),
    __metadata("design:paramtypes", [typeorm_1.Repository])
], TypeOrmUserRepository);
//# sourceMappingURL=typeorm-user.repository.js.map