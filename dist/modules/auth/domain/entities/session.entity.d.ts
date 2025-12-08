export declare class Session {
    id: string;
    userId: number;
    token: string;
    expiresAt: Date;
    ipAddress: string;
    userAgent: string;
    createdAt: Date;
    isExpired(): boolean;
    isValid(): boolean;
}
