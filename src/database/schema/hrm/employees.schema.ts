import { pgTable, serial, text, integer, date, timestamp, bigint, numeric } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from '../core/users.schema';
import { locations, positions } from './org-structure.schema';
import { leads } from '../crm/leads.schema';

// 1. Hồ sơ Nhân viên
export const employees = pgTable('employees', {
    id: serial('id').primaryKey(),
    userId: bigint('user_id', { mode: 'number' })
        .unique() // Vẫn giữ unique để 1 User chỉ map 1 Employee
        .references(() => users.id, { onDelete: 'set null' }), // Đổi cascade thành set null để khi xóa User, hồ sơ NV vẫn còn

    employeeCode: text('employee_code').notNull().unique(), // VD: 001, 007
    fullName: text('full_name').notNull(),
    dateOfBirth: date('date_of_birth'),
    phoneNumber: text('phone_number'),
    avatarUrl: text('avatar_url'),

    // 👉 THAY ĐỔI LỚN: NV liên kết trực tiếp với Vị trí (Position) và Địa điểm (Location)
    locationId: integer('location_id').references(() => locations.id), // Nơi làm việc (HCM)
    positionId: integer('position_id').references(() => positions.id), // Vị trí công việc (Bao hàm cả Phòng, Chức danh, Bậc)

    managerId: integer('manager_id'), // Người quản lý trực tiếp

    joinDate: date('join_date'),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
});

// 2. 🔥 BẢNG MỚI: KỲ ĐÁNH GIÁ (PERFORMANCE REVIEWS - Lộ trình thăng tiến)
export const performanceReviews = pgTable('performance_reviews', {
    id: serial('id').primaryKey(),
    employeeId: integer('employee_id').notNull().references(() => employees.id, { onDelete: 'cascade' }),
    reviewerId: integer('reviewer_id').references(() => employees.id), // Người đánh giá (Manager)

    reviewPeriod: text('review_period').notNull(), // VD: "Q1-2026"
    score: numeric('score', { precision: 5, scale: 2 }), // Điểm đánh giá
    comments: text('comments'),

    // Đề xuất sau đánh giá
    proposedPositionId: integer('proposed_position_id').references(() => positions.id), // Đề xuất lên vị trí/bậc mới
    status: text('status').default('PENDING'), // PENDING, APPROVED, REJECTED

    createdAt: timestamp('created_at').defaultNow(),
});

// --- RELATIONS ---
export const employeesRelations = relations(employees, ({ one, many }) => ({
    user: one(users, { fields: [employees.userId], references: [users.id] }),
    location: one(locations, { fields: [employees.locationId], references: [locations.id] }),

    // Liên kết chặt chẽ với Ma trận Vị trí
    position: one(positions, { fields: [employees.positionId], references: [positions.id] }),

    // 👈 THÊM 2 DÒNG NÀY ĐỂ KHỚP VỚI LEADS:
    assignedLeads: many(leads, { relationName: 'assignedLeads' }),
    createdLeads: many(leads, { relationName: 'createdLeads' }),

    manager: one(employees, {
        fields: [employees.managerId],
        references: [employees.id],
        relationName: 'employee_management',
    }),
    subordinates: many(employees, { relationName: 'employee_management' }),
    reviews: many(performanceReviews, { relationName: 'employeeReviews' }),
}));

export const performanceReviewsRelations = relations(performanceReviews, ({ one }) => ({
    employee: one(employees, { fields: [performanceReviews.employeeId], references: [employees.id], relationName: 'employeeReviews' }),
    reviewer: one(employees, { fields: [performanceReviews.reviewerId], references: [employees.id] }),
    proposedPosition: one(positions, { fields: [performanceReviews.proposedPositionId], references: [positions.id] }),
}));

