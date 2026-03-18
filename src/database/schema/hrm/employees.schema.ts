import { pgTable, serial, text, integer, date, timestamp, bigint } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from '../core/users.schema';
import { orgUnits, jobTitles, grades } from './org-structure.schema';

export const employees = pgTable('employees', {
    id: serial('id').primaryKey(),

    // FK trỏ về Users (One-to-One)
    userId: bigint('user_id', { mode: 'number' })
        .notNull()
        .unique()
        .references(() => users.id, { onDelete: 'cascade' }),

    // Thông tin cá nhân & Liên hệ
    employeeCode: text('employee_code').notNull().unique(), // Mã NV (VD: NV-0001)
    fullName: text('full_name').notNull(),
    dateOfBirth: date('date_of_birth'),
    phoneNumber: text('phone_number'),
    avatarUrl: text('avatar_url'),

    // Công việc & Tổ chức (FK)
    orgUnitId: integer('org_unit_id').references(() => orgUnits.id), // Thuộc phòng ban
    jobTitleId: integer('job_title_id').references(() => jobTitles.id), // Chức danh
    gradeId: integer('grade_id').references(() => grades.id), // Cấp bậc

    // Cấp trên trực tiếp (Self-referencing)
    managerId: integer('manager_id'),

    // Tracking
    joinDate: date('join_date'),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
});

// --- RELATIONS ---
export const employeesRelations = relations(employees, ({ one, many }) => ({
    // 1 Profile thuộc về 1 Identity User
    user: one(users, { fields: [employees.userId], references: [users.id] }),

    // Thuộc về Phòng ban, Chức danh, Cấp bậc
    orgUnit: one(orgUnits, { fields: [employees.orgUnitId], references: [orgUnits.id] }),
    jobTitle: one(jobTitles, { fields: [employees.jobTitleId], references: [jobTitles.id] }),
    grade: one(grades, { fields: [employees.gradeId], references: [grades.id] }),

    // Quản lý trực tiếp (Sếp)
    manager: one(employees, { fields: [employees.managerId], references: [employees.id], relationName: 'managerRelation' }),

    // Những nhân viên cấp dưới báo cáo cho người này
    subordinates: many(employees, { relationName: 'managerRelation' }),
}));
