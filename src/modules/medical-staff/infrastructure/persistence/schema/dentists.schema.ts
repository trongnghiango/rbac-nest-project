import {
  pgTable,
  serial,
  text,
  timestamp,
  integer,
  jsonb,
  date,
  boolean,
  index,
  pgEnum,
  numeric,
  bigint,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
// FIX: Import cross-modules (Sử dụng Alias @database/schema để tránh đường dẫn relative dài dòng)
// Bạn cần đảm bảo trong tsconfig.json đã cấu hình paths: { "@database/*": ["src/database/*"] }
import { users } from '@database/schema/users.schema';
import * as schema from '@database/schema';
import { cases, clinics } from '@database/schema'; // Fallback cho các bảng khác

export const dentists = pgTable('dentists', {
  id: serial('id').primaryKey(),
  userId: bigint('user_id', { mode: 'number' }).references(() => users.id),
  clinicId: integer('clinic_id').references(() => schema.clinics.id),
  fullName: text('full_name').notNull(),
  phoneNumber: text('phone_number'),
  email: text('email'),
  createdAt: timestamp('created_at').defaultNow(),
});

export const dentistsRelations = relations(dentists, ({ one, many }) => ({
  user: one(users, { fields: [dentists.userId], references: [users.id] }),
  clinic: one(clinics, {
    fields: [dentists.clinicId],
    references: [clinics.id],
  }),
  cases: many(cases),
}));
