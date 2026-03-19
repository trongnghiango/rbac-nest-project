// src/database/schema/index.ts

// Core
export * from './core/users.schema';
export * from './core/sessions.schema';

// RBAC
export * from './rbac/rbac.schema';

// System
export * from './system/notifications.schema';

// HRM (Nhân sự)
export * from './hrm/org-structure.schema';
export * from './hrm/employees.schema';

// ✅ BỔ SUNG DÒNG NÀY (CRM - Đối tác/Khách hàng)
export * from './crm/organizations.schema';
