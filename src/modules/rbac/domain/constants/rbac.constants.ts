import { ORG_PERMISSIONS } from "@modules/org-structure/domain/constants/org.permissions";
import { USER_PERMISSIONS } from "@modules/user/domain/constants/user.permissions";

/**
 * 1. CORE ROLES
 * Chỉ khai báo các Role mang tính hệ thống (Bypass quyền, Default User).
 * Tuyệt đối không khai báo MANAGER, STAFF, HR... ở đây.
 */
export const CORE_ROLES = {
  SUPER_ADMIN: 'SUPER_ADMIN', // Thượng phương bảo kiếm (Bypass mọi Guard)
  DEFAULT_USER: 'USER',       // Vai trò mặc định khi có người đăng ký mới
} as const;

/**
 * 2. CORE ACTIONS
 * Các hành động CRUD chuẩn. Dùng để tham chiếu trong code nếu cần, 
 * giúp đồng bộ với file rbac.csv
 */
export const ACTIONS = {
  MANAGE: 'manage', // Toàn quyền (Tương đương *)
  CREATE: 'create',
  READ: 'read',
  UPDATE: 'update',
  DELETE: 'delete',
  EXPORT: 'export',
} as const;

/**
 * 3. HIERARCHY
 * So sánh cấp bậc (Giúp Admin không thể xóa/sửa Super Admin).
 */
export const ROLE_HIERARCHY: Record<string, number> = {
  [CORE_ROLES.SUPER_ADMIN]: 100,
  'ADMIN': 90,
  'MANAGER': 80,
  'STAFF': 70,
  [CORE_ROLES.DEFAULT_USER]: 60,
};

/**
 * 4. BỘ TỪ ĐIỂN QUYỀN (Dành cho Developer)
 * - Đây KHÔNG PHẢI là giới hạn của hệ thống.
 * - Đây chỉ là bộ hằng số để Developer gõ code có Auto-complete, tránh sai chính tả.
 * - Nếu có module mới (VD: payroll), Dev có thể gõ thẳng string 'payroll:view' 
 *   hoặc bổ sung vào đây cho team cùng dùng.
 */
// Nhờ Spread Operator (...), nếu bạn thêm module mới (VD: PAYROLL), 
// bạn chỉ cần import PAYROLL_PERMISSIONS vào đây.
export const PERMISSIONS = {
  // 1. Module đã có file riêng
  ...USER_PERMISSIONS, // user:manage, user:read...
  ...ORG_PERMISSIONS,  // org:manage, org:read, org:update

  // 2. Các quyền Hệ thống
  SYSTEM_CONFIG: 'system:config',
  RBAC_MANAGE: 'rbac:manage',
  AUDIT_VIEW: 'audit:view',

  // 3. Khai báo nhanh các module từ CSV (Sau này có module riêng thì tách ra sau)
  EMPLOYEE_MANAGE: 'employee:manage',
  EMPLOYEE_READ: 'employee:read',
  EMPLOYEE_UPDATE: 'employee:update',

  REPORT_MANAGE: 'report:manage',
  REPORT_VIEW: 'report:view',
  REPORT_EXPORT: 'report:export',

  BOOKING_MANAGE: 'booking:manage',
  BOOKING_CREATE: 'booking:create',
  BOOKING_READ: 'booking:read',
  BOOKING_UPDATE: 'booking:update',
} as const;


// Trích xuất các value thành 1 Type (VD: 'system:config' | 'rbac:manage' | ...)
export type KnownPermission = typeof PERMISSIONS[keyof typeof PERMISSIONS];

// 🚀 MAGIC TRICK: Cho phép Auto-complete các quyền đã biết, 
// nhưng VẪN CHO PHÉP Dev gõ string bất kỳ nếu hệ thống có Module mới!
export type PermissionString = KnownPermission | (string & {});
