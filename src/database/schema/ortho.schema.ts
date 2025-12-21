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
import { users } from './users.schema'; // Link với bảng Users có sẵn

// --- 1. ENUMS (Khớp với nghiệp vụ) ---
export const genderEnum = pgEnum('gender', ['Male', 'Female', 'Other']);
export const productTypeEnum = pgEnum('product_type', ['retainer', 'aligner']);
export const jawTypeEnum = pgEnum('jaw_type', ['Upper', 'Lower']);

// --- 2. BẢNG CLINICS (Phòng khám) ---
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

// --- 3. BẢNG DENTISTS (Bác sĩ) ---
export const dentists = pgTable('dentists', {
  id: serial('id').primaryKey(),
  userId: bigint('user_id', { mode: 'number' }).references(() => users.id),
  clinicId: integer('clinic_id').references(() => clinics.id),
  fullName: text('full_name').notNull(),
  phoneNumber: text('phone_number'),
  email: text('email'),
  createdAt: timestamp('created_at').defaultNow(),
});

// --- 4. BẢNG PATIENTS (Bệnh nhân) ---
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

// --- 5. BẢNG CASES (Ca điều trị) ---
export const cases = pgTable('cases', {
  id: serial('id').primaryKey(),
  orderId: text('order_id').unique(), // ORD-2510...

  patientId: integer('patient_id')
    .references(() => patients.id)
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

// --- 6. BẢNG TREATMENT STEPS (Lưu trữ dữ liệu 3D - JSONB) ---
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

// --- RELATIONS ---
export const clinicsRelations = relations(clinics, ({ one, many }) => ({
  manager: one(users, { fields: [clinics.userId], references: [users.id] }),
  dentists: many(dentists),
  patients: many(patients),
}));

export const dentistsRelations = relations(dentists, ({ one, many }) => ({
  user: one(users, { fields: [dentists.userId], references: [users.id] }),
  clinic: one(clinics, {
    fields: [dentists.clinicId],
    references: [clinics.id],
  }),
  cases: many(cases),
}));

export const patientsRelations = relations(patients, ({ one, many }) => ({
  clinic: one(clinics, {
    fields: [patients.clinicId],
    references: [clinics.id],
  }),
  user: one(users, { fields: [patients.userId], references: [users.id] }),
  cases: many(cases),
}));

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
