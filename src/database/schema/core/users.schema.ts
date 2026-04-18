import { relations } from 'drizzle-orm';
import { pgTable, bigserial, text, boolean, timestamp, varchar, bigint, jsonb } from 'drizzle-orm/pg-core';
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


export const userMetadata = pgTable('user_metadata', {
  userId: bigint('user_id', { mode: 'number' }).primaryKey().references(() => users.id, { onDelete: 'cascade' }),
  fullName: text('full_name'),
  avatarUrl: text('avatar_url'),
  bio: text('bio'),
  phoneNumber: text('phone_number'),
  // Lưu cài đặt UI/UX (Theme, Ngôn ngữ) vào JSONB vì nó không cần query phức tạp
  settings: jsonb('settings').default({ theme: 'light', lang: 'vi' }),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// --- RELATIONS (Nhìn code như nhìn sơ đồ ERD) ---
export const usersRelations = relations(users, ({ one, many }) => ({
  metadata: one(userMetadata),
  // metadata: one(userMetadata, {
  //   fields: [users.id],
  //   references: [userMetadata.userId],
  // }),

  // 1 User có nhiều Roles
  userRoles: many(userRoles),

  // Quan hệ 1-1: 1 User có thể là 1 Nhân viên (HRM)
  employeeProfile: one(employees),

  // Quan hệ 1-1: 1 User có thể là 1 Khách hàng Doanh nghiệp (CRM)
  organizationProfile: one(organizations),
}));


export const userMetadataRelations = relations(userMetadata, ({ one }) => ({
  user: one(users, {
    fields: [userMetadata.userId],
    references: [users.id],
  }),
}));
