import { pgTable, serial, varchar, integer, boolean, timestamp, numeric } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { employees } from './employees.schema';

// 1. Địa điểm làm việc (Chi nhánh, Tòa nhà)
export const locations = pgTable('locations', {
    id: serial('id').primaryKey(),
    code: varchar('code', { length: 50 }).unique().notNull(), // VD: HCM, HN
    name: varchar('name', { length: 255 }).notNull(),
    isActive: boolean('is_active').default(true),
});

// 2. Cấp bậc lương / Rank (Từ Bậc 1 -> Bậc 10 như Hình 2)
export const grades = pgTable('grades', {
    id: serial('id').primaryKey(),
    levelNumber: integer('level_number').notNull().unique(), // 1, 2... 10
    code: varchar('code', { length: 50 }).unique().notNull(), // BAC_1, BAC_10
    name: varchar('name', { length: 255 }).notNull(),
});

// 3. Thang bảng lương (Salary Scales) - Link với Bậc
export const salaryScales = pgTable('salary_scales', {
    id: serial('id').primaryKey(),
    gradeId: integer('grade_id').notNull().references(() => grades.id, { onDelete: 'cascade' }),
    baseSalary: numeric('base_salary', { precision: 15, scale: 2 }), // Lương cơ bản
    coefficient: numeric('coefficient', { precision: 5, scale: 2 }), // Hệ số lương (VD: 2.34)
    effectiveDate: timestamp('effective_date'), // Ngày áp dụng
});

// 4. Chức danh công việc chung (Generic Job Titles)
export const jobTitles = pgTable('job_titles', {
    id: serial('id').primaryKey(),
    name: varchar('name', { length: 255 }).notNull().unique(), // Trưởng phòng, Chuyên viên, Trợ lý...
});

// 5. Cơ cấu tổ chức (Sơ đồ cây: Công ty -> Khối -> Phòng -> Nhóm)
export const orgUnits = pgTable('org_units', {
    id: serial('id').primaryKey(),
    parentId: integer('parent_id'),
    type: varchar('type', { length: 50 }).notNull(), // COMPANY, BOD, DEPARTMENT, TEAM
    code: varchar('code', { length: 50 }).unique().notNull(),
    name: varchar('name', { length: 255 }).notNull(),
    isActive: boolean('is_active').default(true),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
});

// 6. 🔥 BẢNG MỚI: VỊ TRÍ ĐỊNH BIÊN (POSITIONS - MA TRẬN CHỨC DANH)
// Đại diện cho các ô màu vàng/xanh trong Hình 3
export const positions = pgTable('positions', {
    id: serial('id').primaryKey(),
    code: varchar('code', { length: 50 }).unique().notNull(), // VD: POS-IT-06
    name: varchar('name', { length: 255 }).notNull(), // VD: "CV-IT" hoặc "Chuyên viên B2"

    orgUnitId: integer('org_unit_id').notNull().references(() => orgUnits.id), // Thuộc phòng nào
    jobTitleId: integer('job_title_id').notNull().references(() => jobTitles.id), // Mang chức danh gì
    gradeId: integer('grade_id').notNull().references(() => grades.id), // Ở bậc mấy

    headcountLimit: integer('headcount_limit').default(1), // Định biên nhân sự (Số lượng tối đa cho vị trí này)
    isActive: boolean('is_active').default(true),
});

// --- RELATIONS ---
export const orgUnitsRelations = relations(orgUnits, ({ one, many }) => ({
    parent: one(orgUnits, { fields: [orgUnits.parentId], references: [orgUnits.id] }),
    children: many(orgUnits),
    positions: many(positions), // 1 Phòng ban có nhiều Vị trí
}));

export const gradesRelations = relations(grades, ({ many }) => ({
    salaryScales: many(salaryScales),
    positions: many(positions),
}));

export const positionsRelations = relations(positions, ({ one, many }) => ({
    orgUnit: one(orgUnits, { fields: [positions.orgUnitId], references: [orgUnits.id] }),
    jobTitle: one(jobTitles, { fields: [positions.jobTitleId], references: [jobTitles.id] }),
    grade: one(grades, { fields: [positions.gradeId], references: [grades.id] }),
    employees: many(employees), // 1 Vị trí có thể có nhiều nhân viên (nếu headcount > 1)
}));
