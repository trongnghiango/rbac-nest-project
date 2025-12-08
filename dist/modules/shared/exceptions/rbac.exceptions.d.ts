import { HttpException } from '@nestjs/common';
export declare class PermissionDeniedException extends HttpException {
    constructor(permission?: string);
}
export declare class RoleRequiredException extends HttpException {
    constructor(role: string);
}
export declare class UserNotFoundException extends HttpException {
    constructor(userId?: number);
}
export declare class InvalidCredentialsException extends HttpException {
    constructor();
}
