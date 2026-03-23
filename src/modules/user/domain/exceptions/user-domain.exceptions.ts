export class UserDomainException extends Error {
    constructor(public message: string, public code: string) {
        super(message);
    }
}

export class IdentityAlreadyTakenException extends UserDomainException {
    constructor(identifier: string) {
        super(`Thông tin định danh '${identifier}' đã được sử dụng.`, 'IDENTITY_TAKEN');
    }
}
