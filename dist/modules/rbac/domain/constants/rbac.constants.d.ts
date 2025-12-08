export declare enum SystemRole {
    SUPER_ADMIN = "SUPER_ADMIN",
    ADMIN = "ADMIN",
    MANAGER = "MANAGER",
    STAFF = "STAFF",
    USER = "USER",
    GUEST = "GUEST"
}
export declare enum SystemPermission {
    USER_CREATE = "user:create",
    USER_READ = "user:read",
    USER_UPDATE = "user:update",
    USER_DELETE = "user:delete",
    USER_MANAGE = "user:manage",
    BOOKING_CREATE = "booking:create",
    BOOKING_READ = "booking:read",
    BOOKING_UPDATE = "booking:update",
    BOOKING_DELETE = "booking:delete",
    BOOKING_MANAGE = "booking:manage",
    PAYMENT_PROCESS = "payment:process",
    PAYMENT_REFUND = "payment:refund",
    PAYMENT_VIEW = "payment:view",
    REPORT_VIEW = "report:view",
    REPORT_EXPORT = "report:export",
    REPORT_MANAGE = "report:manage",
    SYSTEM_CONFIG = "system:config",
    RBAC_MANAGE = "rbac:manage",
    AUDIT_VIEW = "audit:view"
}
export declare const ROLE_HIERARCHY: Record<SystemRole, number>;
export declare const DEFAULT_ROLE = SystemRole.USER;
