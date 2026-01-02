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

export const genderEnum = pgEnum('gender', ['Male', 'Female', 'Other']);

export const patients = pgTable('patients', {
  id: serial('id').primaryKey(),
  clinicId: integer('clinic_id').references(() => clinics.id),
  userId: bigint('user_id', { mode: 'number' }).references(() => users.id),

  patientCode: text('patient_code').notNull().unique(), // VD: #NK121789
  fullName: text('full_name').notNull(),
  email: text('email'),
  phoneNumber: text('phone_number'),
  address: text('address'),
  birthDate: date('date_of_birth'),
  gender: genderEnum('gender'),

  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export const patientsRelations = relations(patients, ({ one, many }) => ({
  clinic: one(clinics, {
    fields: [patients.clinicId],
    references: [clinics.id],
  }),
  user: one(users, { fields: [patients.userId], references: [users.id] }),
  cases: many(cases),
}));
