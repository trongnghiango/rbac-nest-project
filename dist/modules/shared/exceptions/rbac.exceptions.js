"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidCredentialsException = exports.UserNotFoundException = exports.RoleRequiredException = exports.PermissionDeniedException = void 0;
const common_1 = require("@nestjs/common");
class PermissionDeniedException extends common_1.HttpException {
    constructor(permission) {
        const message = permission
            ? `Permission denied: ${permission}`
            : 'Insufficient permissions';
        super(message, common_1.HttpStatus.FORBIDDEN);
    }
}
exports.PermissionDeniedException = PermissionDeniedException;
class RoleRequiredException extends common_1.HttpException {
    constructor(role) {
        super(`Role required: ${role}`, common_1.HttpStatus.FORBIDDEN);
    }
}
exports.RoleRequiredException = RoleRequiredException;
class UserNotFoundException extends common_1.HttpException {
    constructor(userId) {
        const message = userId ? `User not found: ${userId}` : 'User not found';
        super(message, common_1.HttpStatus.NOT_FOUND);
    }
}
exports.UserNotFoundException = UserNotFoundException;
class InvalidCredentialsException extends common_1.HttpException {
    constructor() {
        super('Invalid credentials', common_1.HttpStatus.UNAUTHORIZED);
    }
}
exports.InvalidCredentialsException = InvalidCredentialsException;
//# sourceMappingURL=rbac.exceptions.js.map