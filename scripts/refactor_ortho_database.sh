#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

log "🦷 REFACTORING DATABASE SCHEMA & REPOSITORIES FOR DENTAL SYSTEM..."

# ============================================================
# 1. TẠO SCHEMA DRIZZLE (Mapping từ Python Model)
# ============================================================
log "1️⃣ Creating 'ortho.schema.ts'..."

cat > src/database/schema/ortho.schema.ts << 'EOF'
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

  patientId: integer('patient_id').references(() => patients.id).notNull(),
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
export const treatmentSteps = pgTable('treatment_steps', {
  id: serial('id').primaryKey(),
  caseId: integer('case_id').references(() => cases.id).notNull(),
  stepIndex: integer('step_index').notNull(), // 0, 1, 2...

  // JSONB chứa toàn bộ thông số di chuyển (Torque, Angulation...)
  teethData: jsonb('teeth_data').notNull(),

  hasIpr: boolean('has_ipr').default(false),
  hasAttachments: boolean('has_attachments').default(false),

  createdAt: timestamp('created_at').defaultNow(),
}, (table) => ({
  caseStepIdx: index('idx_case_step').on(table.caseId, table.stepIndex),
}));

// --- RELATIONS ---
export const clinicsRelations = relations(clinics, ({ one, many }) => ({
  manager: one(users, { fields: [clinics.userId], references: [users.id] }),
  dentists: many(dentists),
  patients: many(patients),
}));

export const dentistsRelations = relations(dentists, ({ one, many }) => ({
  user: one(users, { fields: [dentists.userId], references: [users.id] }),
  clinic: one(clinics, { fields: [dentists.clinicId], references: [clinics.id] }),
  cases: many(cases),
}));

export const patientsRelations = relations(patients, ({ one, many }) => ({
  clinic: one(clinics, { fields: [patients.clinicId], references: [clinics.id] }),
  user: one(users, { fields: [patients.userId], references: [users.id] }),
  cases: many(cases),
}));

export const casesRelations = relations(cases, ({ one, many }) => ({
  patient: one(patients, { fields: [cases.patientId], references: [patients.id] }),
  dentist: one(dentists, { fields: [cases.dentistId], references: [dentists.id] }),
  steps: many(treatmentSteps),
}));

export const treatmentStepsRelations = relations(treatmentSteps, ({ one }) => ({
  case: one(cases, { fields: [treatmentSteps.caseId], references: [cases.id] }),
}));
EOF

# ============================================================
# 2. CẬP NHẬT INDEX SCHEMA
# ============================================================
log "2️⃣ Exporting new schema in 'index.ts'..."
if ! grep -q "ortho.schema" src/database/schema/index.ts; then
  echo "export * from './ortho.schema';" >> src/database/schema/index.ts
fi

# ============================================================
# 3. TẠO REPOSITORY INTERFACE (PORT)
# ============================================================
log "3️⃣ Creating Repository Port (Interface)..."
mkdir -p src/modules/dental/domain/repositories

cat > src/modules/dental/domain/repositories/ortho.repository.ts << 'EOF'
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

// Định nghĩa kiểu dữ liệu trả về (tạm thời dùng any hoặc type specific)
export interface OrthoCase {
  id: number;
  orderId: string | null;
  patientId: number;
  status: string | null;
  createdAt: Date | null;
}

export interface CreateCaseParams {
  patientId: number;
  dentistId?: number;
  productType: 'aligner' | 'retainer';
  scanDate?: Date;
}

export const IOrthoRepository = Symbol('IOrthoRepository');

export interface IOrthoRepository {
  // Clinic & Patient
  findPatientByCode(code: string, tx?: Transaction): Promise<any | null>;
  createPatient(data: any, tx?: Transaction): Promise<any>;

  // Case
  createCase(data: CreateCaseParams, tx?: Transaction): Promise<OrthoCase>;
  findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null>;

  // Steps (3D Data)
  saveSteps(caseId: number, steps: any[], tx?: Transaction): Promise<void>;
  getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]>;
}
EOF

# ============================================================
# 4. TẠO REPOSITORY IMPLEMENTATION (DRIZZLE ADAPTER)
# ============================================================
log "4️⃣ Creating Drizzle Repository Implementation..."
mkdir -p src/modules/dental/infrastructure/persistence

cat > src/modules/dental/infrastructure/persistence/drizzle-ortho.repository.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { eq, asc } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  IOrthoRepository,
  CreateCaseParams,
  OrthoCase
} from '../../domain/repositories/ortho.repository';
import {
  patients,
  cases,
  treatmentSteps,
  clinics,
  dentists
} from '@database/schema/ortho.schema';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleOrthoRepository extends DrizzleBaseRepository implements IOrthoRepository {

  // --- Patient ---
  async findPatientByCode(code: string, tx?: Transaction): Promise<any | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(patients).where(eq(patients.patientCode, code));
    return result[0] || null;
  }

  async createPatient(data: any, tx?: Transaction): Promise<any> {
    const db = this.getDb(tx);
    const [newPatient] = await db.insert(patients).values(data).returning();
    return newPatient;
  }

  // --- Case ---
  async createCase(data: CreateCaseParams, tx?: Transaction): Promise<OrthoCase> {
    const db = this.getDb(tx);
    const [newCase] = await db.insert(cases).values({
        patientId: data.patientId,
        dentistId: data.dentistId,
        productType: data.productType,
        status: 'PLANNING',
        scanDate: data.scanDate || new Date(),
    }).returning();

    return newCase;
  }

  async findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null> {
    const db = this.getDb(tx);
    // Dùng query builder để join nếu cần
    const result = await db.query.cases.findFirst({
        where: eq(cases.id, id),
        with: {
            patient: true,
            dentist: true,
            steps: true
        }
    });
    return result as unknown as OrthoCase;
  }

  // --- Steps (JSONB Data) ---
  async saveSteps(caseId: number, stepsData: any[], tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);

    // Batch Insert hiệu năng cao
    if (stepsData.length > 0) {
        // Xóa steps cũ nếu update lại plan
        await db.delete(treatmentSteps).where(eq(treatmentSteps.caseId, caseId));

        await db.insert(treatmentSteps).values(stepsData.map(s => ({
            caseId,
            stepIndex: s.index,
            teethData: s.teethMap, // JSONB object từ worker
            hasIpr: s.hasIpr || false,
            hasAttachments: s.hasAttachments || false
        })));
    }
  }

  async getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]> {
    const db = this.getDb(tx);
    return await db.select()
        .from(treatmentSteps)
        .where(eq(treatmentSteps.caseId, caseId))
        .orderBy(asc(treatmentSteps.stepIndex));
  }
}
EOF

# ============================================================
# 5. CẬP NHẬT MODULE (PROVIDE REPOSITORY)
# ============================================================
log "5️⃣ Updating DentalModule to provide Repository..."

cat > src/modules/dental/dental.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DentalController } from './infrastructure/controllers/dental.controller';
import { DentalService } from './application/services/dental.service';
import { PiscinaProvider } from './infrastructure/workers/piscina.provider';
import { FileSystemDentalStorage } from './infrastructure/adapters/fs-dental-storage.adapter';
import { PiscinaDentalWorker } from './infrastructure/adapters/piscina-worker.adapter';
import { DrizzleOrthoRepository } from './infrastructure/persistence/drizzle-ortho.repository';
import { IDentalStorage } from './domain/ports/dental-storage.port';
import { IDentalWorker } from './domain/ports/dental-worker.port';
import { IOrthoRepository } from './domain/repositories/ortho.repository';
import dentalConfig from '@config/dental.config';

@Module({
  imports: [ConfigModule.forFeature(dentalConfig)],
  controllers: [DentalController],
  providers: [
    DentalService,
    PiscinaProvider,
    {
      provide: IDentalStorage,
      useClass: FileSystemDentalStorage,
    },
    {
      provide: IDentalWorker,
      useClass: PiscinaDentalWorker,
    },
    // ✅ Đăng ký Repository mới
    {
      provide: IOrthoRepository,
      useClass: DrizzleOrthoRepository
    }
  ],
})
export class DentalModule {}
EOF

success "✅ DATABASE REFACTORING COMPLETE!"
warn "⚠️ NEXT STEPS:"
echo "1. Run DB Migration: npx drizzle-kit push"
echo "2. Restart Server: npm run start:dev"