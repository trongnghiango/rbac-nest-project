import {
  pgTable,
  serial,
  text,
  boolean,
  timestamp,
  primaryKey,
  bigint,
  integer,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// --- 1. TABLES DEFINITIONS ---

// Permissions Table
export const permissions = pgTable('permissions', {
  id: serial('id').primaryKey(),
  name: text('name').notNull().unique(),
  description: text('description'),
  resourceType: text('resourceType'),
  action: text('action'),
  attributes: text('attributes').default('*'),
  isActive: boolean('isActive').default(true),
  createdAt: timestamp('createdAt').defaultNow(),
});

// Roles Table
export const roles = pgTable('roles', {
  id: serial('id').primaryKey(),
  name: text('name').notNull().unique(),
  description: text('description'),
  isActive: boolean('isActive').default(true),
  isSystem: boolean('isSystem').default(false),
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
});

// User Roles (Pivot Table: Users <-> Roles)
export const userRoles = pgTable(
  'user_roles',
  {
    userId: bigint('userId', { mode: 'number' }).notNull(),
    roleId: integer('roleId') // Lưu ý: DB column name nên để 'role_id' nếu muốn chuẩn snake_case, ở đây giữ nguyên theo code cũ của bạn
      .notNull()
      .references(() => roles.id),
    assignedBy: bigint('assignedBy', { mode: 'number' }),
    expiresAt: timestamp('expiresAt', { withTimezone: true }),
    assignedAt: timestamp('assignedAt').defaultNow(),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.userId, t.roleId] }),
  }),
);

// Role Permissions (Pivot Table: Roles <-> Permissions)
export const rolePermissions = pgTable(
  'role_permissions',
  {
    roleId: integer('role_id')
      .notNull()
      .references(() => roles.id),
    permissionId: integer('permission_id')
      .notNull()
      .references(() => permissions.id),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.roleId, t.permissionId] }),
  }),
);

// --- 2. RELATIONS DEFINITIONS ---

// Relations cho Permissions
export const permissionsRelations = relations(permissions, ({ many }) => ({
  roles: many(rolePermissions), // Permission có nhiều entry trong bảng nối rolePermissions
}));

// Relations cho Roles
export const rolesRelations = relations(roles, ({ many }) => ({
  permissions: many(rolePermissions), // Role có nhiều entry trong bảng nối rolePermissions
  // Nếu bạn muốn query ngược từ Role ra User, cần relation này (Optional)
  users: many(userRoles),
}));

// Relations cho RolePermissions (Bảng nối)
export const rolePermissionsRelations = relations(
  rolePermissions,
  ({ one }) => ({
    role: one(roles, {
      fields: [rolePermissions.roleId],
      references: [roles.id],
    }),
    permission: one(permissions, {
      fields: [rolePermissions.permissionId],
      references: [permissions.id],
    }),
  }),
);

// Relations cho UserRoles (Bảng nối) - PHẦN BỊ THIẾU GÂY LỖI
export const userRolesRelations = relations(userRoles, ({ one }) => ({
  role: one(roles, {
    fields: [userRoles.roleId],
    references: [roles.id],
  }),
  // Chúng ta chưa import bảng 'users' ở đây để tránh Circular Dependency.
  // Nếu cần query user từ bảng nối này, cần import 'users' cẩn thận.
  // Hiện tại chỉ cần 'role' để Drizzle hiểu graph khi query từ Role.
}));
