import { relations } from 'drizzle-orm';
import { pgTable, bigserial, text, boolean, timestamp, varchar } from 'drizzle-orm/pg-core';
import { userRoles } from '../rbac/rbac.schema';
import { employees } from '../hrm/employees.schema';
import { organizations } from '../crm/organizations.schema';

// --- TABLE ---
export const users = pgTable('users', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  username: text('username').notNull().unique(),
  email: text('email').unique(),
  hashedPassword: text('hashedPassword'),
  telegramId: varchar('telegram_id', { length: 50 }).unique(), // Dùng cho Chatbot

  isActive: boolean('is_active').default(true),

  deletedAt: timestamp('deleted_at'),

  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// --- RELATIONS (Nhìn code như nhìn sơ đồ ERD) ---
export const usersRelations = relations(users, ({ one, many }) => ({
  // 1 User có nhiều Roles
  userRoles: many(userRoles),

  // Quan hệ 1-1: 1 User có thể là 1 Nhân viên (HRM)
  employeeProfile: one(employees, {
    fields: [users.id],
    references: [employees.userId],
  }),

  // Quan hệ 1-1: 1 User có thể là 1 Khách hàng Doanh nghiệp (CRM)
  organizationProfile: one(organizations, {
    fields: [users.id],
    references: [organizations.userId],
  }),
}));
