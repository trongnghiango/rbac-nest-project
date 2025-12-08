import { HttpException, HttpStatus } from '@nestjs/common';

export class PermissionDeniedException extends HttpException {
  constructor(permission?: string) {
    const message = permission
      ? `Permission denied: ${permission}`
      : 'Insufficient permissions';
    super(message, HttpStatus.FORBIDDEN);
  }
}

export class RoleRequiredException extends HttpException {
  constructor(role: string) {
    super(`Role required: ${role}`, HttpStatus.FORBIDDEN);
  }
}

export class UserNotFoundException extends HttpException {
  constructor(userId?: number) {
    const message = userId ? `User not found: ${userId}` : 'User not found';
    super(message, HttpStatus.NOT_FOUND);
  }
}

export class InvalidCredentialsException extends HttpException {
  constructor() {
    super('Invalid credentials', HttpStatus.UNAUTHORIZED);
  }
}
