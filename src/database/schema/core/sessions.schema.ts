import {
  pgTable,
  uuid,
  bigint,
  text,
  timestamp,
  index,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from './users.schema';

/**
 * SESSIONS — Phiên làm việc (JWT + Refresh Token)
 *
 * FIX: Thêm index trên cột token và refresh_token.
 * Lý do: JwtStrategy gọi WHERE token = ? trên mỗi API request.
 * Không có index = full table scan với mỗi request.
 */
export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: bigint('user_id', { mode: 'number' })
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    token: text('token').notNull(),
    refreshToken: text('refresh_token').notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => ({
    // Index gốc (đã có)
    userIdIdx: index('idx_sessions_user_id').on(table.userId),

    // FIX: Thêm 2 index này — critical cho performance
    // JwtStrategy: WHERE token = ? (mỗi API request)
    tokenIdx: index('idx_sessions_token').on(table.token),

    // AuthService.refreshToken: WHERE refresh_token = ?
    refreshTokenIdx: index('idx_sessions_refresh_token').on(table.refreshToken),
  }),
);

// --- RELATIONS ---
export const sessionsRelations = relations(sessions, ({ one }) => ({
  user: one(users, {
    fields: [sessions.userId],
    references: [users.id],
  }),
}));
