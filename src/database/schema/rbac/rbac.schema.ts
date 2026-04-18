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
import { users } from '../core/users.schema';

/**
 * FIX: Đổi toàn bộ tên cột DB sang snake_case để nhất quán với các schema khác.
 * Drizzle field (camelCase) vẫn giữ nguyên để không cần sửa code application.
 *
 * TRƯỚC (lỗi):  userId: bigint('userId')       ← tên cột DB bị camelCase
 * SAU  (đúng):  userId: bigint('user_id')       ← tên cột DB là snake_case
 */

// --- PERMISSIONS ---
export const permissions = pgTable('permissions', {
  id: serial('id').primaryKey(),
  name: text('name').notNull().unique(),
  description: text('description'),
  resourceType: text('resource_type'),   // FIX: 'resourceType' → 'resource_type'
  action: text('action'),
  attributes: text('attributes').default('*'),
  isActive: boolean('is_active').default(true),     // FIX: 'isActive' → 'is_active'
  createdAt: timestamp('created_at').defaultNow(),  // FIX: 'createdAt' → 'created_at'
});

// --- ROLES ---
export const roles = pgTable('roles', {
  id: serial('id').primaryKey(),
  name: text('name').notNull().unique(),
  description: text('description'),
  isActive: boolean('is_active').default(true),     // FIX: 'isActive' → 'is_active'
  isSystem: boolean('is_system').default(false),    // FIX: 'isSystem' → 'is_system'
  createdAt: timestamp('created_at').defaultNow(),  // FIX: 'createdAt' → 'created_at'
  updatedAt: timestamp('updated_at').defaultNow(),  // FIX: 'updatedAt' → 'updated_at'
});

// --- USER_ROLES (Pivot: Users <-> Roles) ---
export const userRoles = pgTable(
  'user_roles',
  {
    userId: bigint('user_id', { mode: 'number' })   // FIX: 'userId' → 'user_id'
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    roleId: integer('role_id')                       // FIX: 'roleId' → 'role_id'
      .notNull()
      .references(() => roles.id, { onDelete: 'cascade' }),
    assignedBy: bigint('assigned_by', { mode: 'number' }), // FIX: 'assignedBy' → 'assigned_by'
    expiresAt: timestamp('expires_at', { withTimezone: true }),  // FIX: 'expiresAt' → 'expires_at'
    assignedAt: timestamp('assigned_at').defaultNow(),           // FIX: 'assignedAt' → 'assigned_at'
  },
  (t) => ({
    pk: primaryKey({ columns: [t.userId, t.roleId] }),
  }),
);

// --- ROLE_PERMISSIONS (Pivot: Roles <-> Permissions) ---
export const rolePermissions = pgTable(
  'role_permissions',
  {
    roleId: integer('role_id')
      .notNull()
      .references(() => roles.id, { onDelete: 'cascade' }),
    permissionId: integer('permission_id')
      .notNull()
      .references(() => permissions.id, { onDelete: 'cascade' }),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.roleId, t.permissionId] }),
  }),
);

// --- RELATIONS ---
export const permissionsRelations = relations(permissions, ({ many }) => ({
  roles: many(rolePermissions),
}));

export const rolesRelations = relations(roles, ({ many }) => ({
  permissions: many(rolePermissions),
  users: many(userRoles),
}));

export const rolePermissionsRelations = relations(rolePermissions, ({ one }) => ({
  role: one(roles, {
    fields: [rolePermissions.roleId],
    references: [roles.id],
  }),
  permission: one(permissions, {
    fields: [rolePermissions.permissionId],
    references: [permissions.id],
  }),
}));

export const userRolesRelations = relations(userRoles, ({ one }) => ({
  role: one(roles, {
    fields: [userRoles.roleId],
    references: [roles.id],
  }),
  user: one(users, {
    fields: [userRoles.userId],
    references: [users.id],
  }),
}));
