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
import { patients, dentists } from '@database/schema'; // Fallback cho các bảng khác

export const clinics = pgTable('clinics', {
  id: serial('id').primaryKey(),
  // Dùng bigint vì users.id thường là bigserial
  userId: bigint('user_id', { mode: 'number' }).references(() => users.id),
  name: text('name').notNull(),
  clinicCode: text('clinic_code').notNull().unique(), // VD: NK1
  address: text('address'),
  phoneNumber: text('phone_number'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export const clinicsRelations = relations(clinics, ({ one, many }) => ({
  manager: one(users, { fields: [clinics.userId], references: [users.id] }),
  dentists: many(dentists),
  patients: many(patients),
}));
