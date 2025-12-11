import {
  pgTable,
  bigserial,
  text,
  boolean,
  timestamp,
  jsonb,
} from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  username: text('username').notNull().unique(),
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
