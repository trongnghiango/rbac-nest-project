import { relations } from 'drizzle-orm';
import {
  pgTable,
  bigserial,
  text,
  boolean,
  timestamp,
  jsonb,
  varchar,
} from 'drizzle-orm/pg-core';

import { userRoles } from '@database/schema';

export const users = pgTable('users', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  username: text('username').notNull().unique(),
  telegramId: varchar('telegram_id', { length: 50 }).unique(),
  email: text('email').unique(), // Nullable by default
  hashedPassword: text('hashedPassword'),

  fullName: text('fullName'),
  isActive: boolean('isActive').default(true),
  phoneNumber: text('phoneNumber'),
  avatarUrl: text('avatarUrl'),
  profile: jsonb('profile'),
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
});

// ✅ Định nghĩa Relation: Một User có nhiều Role (thông qua bảng nối userRoles)
export const usersRelations = relations(users, ({ many }) => ({
  userRoles: many(userRoles),
}));