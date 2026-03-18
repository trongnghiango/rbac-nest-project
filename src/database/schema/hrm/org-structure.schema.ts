import { pgTable, serial, varchar, integer, boolean, timestamp } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// 1. Địa điểm (Locations)
export const locations = pgTable('locations', {
    id: serial('id').primaryKey(),
    code: varchar('code', { length: 50 }).unique().notNull(), // HCM, HN...
    name: varchar('name', { length: 255 }).notNull(),
    isActive: boolean('is_active').default(true),
});

// 2. Cấp bậc (Grades)
export const grades = pgTable('grades', {
    id: serial('id').primaryKey(),
    levelNumber: integer('level_number').notNull(), // 1, 2, 3...
    code: varchar('code', { length: 50 }).unique().notNull(), // A1, B2...
    name: varchar('name', { length: 255 }).notNull(), // Trợ lý A1...
});

// 3. Chức danh (Job Titles)
export const jobTitles = pgTable('job_titles', {
    id: serial('id').primaryKey(),
    name: varchar('name', { length: 255 }).notNull().unique(), // Giám đốc, Trưởng phòng...
});

// 4. Cơ cấu tổ chức (Org Units - Cây phân cấp)
export const orgUnits = pgTable('org_units', {
    id: serial('id').primaryKey(),
    parentId: integer('parent_id'), // Soft FK or Hard FK tự tham chiếu
    type: varchar('type', { length: 50 }).notNull(), // COMPANY, BRANCH, DEPARTMENT, TEAM
    code: varchar('code', { length: 50 }).unique().notNull(),
    name: varchar('name', { length: 255 }).notNull(),
    isActive: boolean('is_active').default(true),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
});

// Định nghĩa quan hệ cha-con cho Drizzle
export const orgUnitsRelations = relations(orgUnits, ({ one, many }) => ({
    parent: one(orgUnits, { fields: [orgUnits.parentId], references: [orgUnits.id] }),
    children: many(orgUnits),
}));
