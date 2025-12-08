"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_ROLE = exports.ROLE_HIERARCHY = exports.SystemPermission = exports.SystemRole = void 0;
var SystemRole;
(function (SystemRole) {
    SystemRole["SUPER_ADMIN"] = "SUPER_ADMIN";
    SystemRole["ADMIN"] = "ADMIN";
    SystemRole["MANAGER"] = "MANAGER";
    SystemRole["STAFF"] = "STAFF";
    SystemRole["USER"] = "USER";
    SystemRole["GUEST"] = "GUEST";
})(SystemRole || (exports.SystemRole = SystemRole = {}));
var SystemPermission;
(function (SystemPermission) {
    SystemPermission["USER_CREATE"] = "user:create";
    SystemPermission["USER_READ"] = "user:read";
    SystemPermission["USER_UPDATE"] = "user:update";
    SystemPermission["USER_DELETE"] = "user:delete";
    SystemPermission["USER_MANAGE"] = "user:manage";
    SystemPermission["BOOKING_CREATE"] = "booking:create";
    SystemPermission["BOOKING_READ"] = "booking:read";
    SystemPermission["BOOKING_UPDATE"] = "booking:update";
    SystemPermission["BOOKING_DELETE"] = "booking:delete";
    SystemPermission["BOOKING_MANAGE"] = "booking:manage";
    SystemPermission["PAYMENT_PROCESS"] = "payment:process";
    SystemPermission["PAYMENT_REFUND"] = "payment:refund";
    SystemPermission["PAYMENT_VIEW"] = "payment:view";
    SystemPermission["REPORT_VIEW"] = "report:view";
    SystemPermission["REPORT_EXPORT"] = "report:export";
    SystemPermission["REPORT_MANAGE"] = "report:manage";
    SystemPermission["SYSTEM_CONFIG"] = "system:config";
    SystemPermission["RBAC_MANAGE"] = "rbac:manage";
    SystemPermission["AUDIT_VIEW"] = "audit:view";
})(SystemPermission || (exports.SystemPermission = SystemPermission = {}));
exports.ROLE_HIERARCHY = {
    [SystemRole.SUPER_ADMIN]: 100,
    [SystemRole.ADMIN]: 90,
    [SystemRole.MANAGER]: 80,
    [SystemRole.STAFF]: 70,
    [SystemRole.USER]: 60,
    [SystemRole.GUEST]: 50,
};
exports.DEFAULT_ROLE = SystemRole.USER;
//# sourceMappingURL=rbac.constants.js.map