import { pgTable, serial, text, timestamp, bigint, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from '../core/users.schema';
import { leads } from './leads.schema';
import { contracts } from './contracts.schema';
import { quotes } from './quotes.schema';

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

        // FK trỏ về Users — NULLABLE (FIX so với bản cũ dùng .notNull())
        // Chỉ tạo User khi org trở thành ACTIVE_CUSTOMER và cần Portal login
        user_id: bigint('user_id', { mode: 'number' })
            .unique()
            .references(() => users.id, { onDelete: 'set null' }),

        company_name: text('company_name').notNull(),
        tax_code: text('tax_code').unique(),   // Mã số thuế
        industry: text('industry'),            // IT | HEALTHCARE | MANUFACTURING | RETAIL | OTHER
        website: text('website'),
        address: text('address'),

        // Đầu mối liên hệ chính
        contact_person: text('contact_person'),
        contact_phone: text('contact_phone'),
        contact_email: text('contact_email'),

        // Trạng thái quan hệ
        status: text('status').default('LEAD').notNull(),
        // LEAD | ACTIVE_CUSTOMER | CHURNED

        // Ghi chú nội bộ
        note: text('note'),

        created_at: timestamp('created_at').defaultNow().notNull(),
        updated_at: timestamp('updated_at').defaultNow().notNull(),
    },
    (table) => ({
        status_idx: index('idx_organizations_status').on(table.status),
    }),
);

// --- RELATIONS ---
export const organizationsRelations = relations(organizations, ({ one, many }) => ({
    user: one(users, {
        fields: [organizations.user_id],
        references: [users.id],
    }),
    leads: many(leads),
    contracts: many(contracts),
    quotes: many(quotes),
}));

