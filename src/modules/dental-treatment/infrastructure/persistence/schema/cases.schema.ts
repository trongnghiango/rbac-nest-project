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
import { dentists, patients } from '@database/schema'; // Fallback cho các bảng khác

export const productTypeEnum = pgEnum('product_type', ['retainer', 'aligner']);

export const jawTypeEnum = pgEnum('jaw_type', ['Upper', 'Lower']);

export const cases = pgTable('cases', {
  id: serial('id').primaryKey(),
  orderId: text('order_id').unique(), // ORD-2510...

  patientId: integer('patient_id')
    .references(() => schema.patients.id)
    .notNull(),
  dentistId: integer('dentist_id').references(() => dentists.id),

  productType: productTypeEnum('product_type').notNull(),
  status: text('status').default('PLANNING'),

  notes: text('notes'),
  price: numeric('price', { precision: 12, scale: 2 }),

  scanDate: timestamp('scan_date'),
  dateDue: timestamp('date_due'),
  startedAt: timestamp('started_at'),

  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export const treatmentSteps = pgTable(
  'treatment_steps',
  {
    id: serial('id').primaryKey(),
    caseId: integer('case_id')
      .references(() => cases.id)
      .notNull(),
    stepIndex: integer('step_index').notNull(), // 0, 1, 2...

    // JSONB chứa toàn bộ thông số di chuyển (Torque, Angulation...)
    teethData: jsonb('teeth_data').notNull(),

    hasIpr: boolean('has_ipr').default(false),
    hasAttachments: boolean('has_attachments').default(false),

    createdAt: timestamp('created_at').defaultNow(),
  },
  (table) => ({
    caseStepIdx: index('idx_case_step').on(table.caseId, table.stepIndex),
  }),
);

export const casesRelations = relations(cases, ({ one, many }) => ({
  patient: one(patients, {
    fields: [cases.patientId],
    references: [patients.id],
  }),
  dentist: one(dentists, {
    fields: [cases.dentistId],
    references: [dentists.id],
  }),
  steps: many(treatmentSteps),
}));

export const treatmentStepsRelations = relations(treatmentSteps, ({ one }) => ({
  case: one(cases, { fields: [treatmentSteps.caseId], references: [cases.id] }),
}));
