import { pgTable, serial, text, timestamp, bigint, boolean, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from '../core/users.schema';
import { leads } from './leads.schema';
import { contracts } from './contracts.schema';
import { quotes } from './quotes.schema';
import { contacts } from './contacts.schema';
import { serviceAssignments } from './service-assignments.schema';
import { orgUnits } from '../hrm/org-structure.schema';
import { employees } from '../hrm/employees.schema';

/**
 * ORGANIZATIONS — Hồ sơ Doanh nghiệp / Đối tác B2B
 *
 * FIX: userId đổi thành nullable (bỏ .notNull())
 * Lý do: Lead mới chưa xác định, chưa có tài khoản đăng nhập.
 * Tài khoản chỉ được tạo khi Organization chuyển sang ACTIVE_CUSTOMER.
 *
 * Luồng status:
 *   LEAD → ACTIVE_CUSTOMER → CHURNED
 */
export const organizations = pgTable(
    'organizations',
    {
        id: serial('id').primaryKey(),
        user_id: bigint('user_id', { mode: 'number' }).unique().references(() => users.id, { onDelete: 'set null' }),

        // ĐÁNH DẤU CHỦ QUẢN (STAX) vs KHÁCH HÀNG
        is_internal: boolean('is_internal').default(false).notNull(),

        company_name: text('company_name').notNull(),
        tax_code: text('tax_code').unique(),

        // ĐÂY LÀ CỘT BỊ THIẾU Ở CODE TRƯỚC
        type: text('type').default('INDIVIDUAL'), // 'INDIVIDUAL' | 'ENTERPRISE'

        industry: text('industry'),
        website: text('website'),
        address: text('address'),

        // LƯU Ý: Đã xóa contact_person, contact_phone, contact_email (Chuyển sang bảng contacts)

        status: text('status').default('PROSPECT').notNull(), // PROSPECT, ACTIVE, INACTIVE, CHURNED
        note: text('note'),
        created_at: timestamp('created_at').defaultNow().notNull(),
        updated_at: timestamp('updated_at').defaultNow().notNull(),
    },
    (table) => ({
        status_idx: index('idx_organizations_status').on(table.status),
        internal_idx: index('idx_organizations_internal').on(table.is_internal),
    }),
);

export const organizationsRelations = relations(organizations, ({ one, many }) => ({
    user: one(users, {
        fields: [organizations.user_id],
        references: [users.id],
    }),
    // Liên kết CRM
    contacts: many(contacts),
    leads: many(leads),
    contracts: many(contracts),
    quotes: many(quotes),
    serviceAssignments: many(serviceAssignments),
    // Liên kết HRM (Multi-tenant)
    orgUnits: many(orgUnits),
    employees: many(employees),
}));