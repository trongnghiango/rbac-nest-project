import { pgTable, serial, text, timestamp, bigint } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from '../core/users.schema';

export const organizations = pgTable('organizations', {
    id: serial('id').primaryKey(),

    // FK trỏ về Users (One-to-One) để đăng nhập cổng Portal CRM
    userId: bigint('user_id', { mode: 'number' })
        .notNull()
        .unique()
        .references(() => users.id, { onDelete: 'cascade' }),

    companyName: text('company_name').notNull(),
    taxCode: text('tax_code').unique(), // Mã số thuế
    industry: text('industry'), // IT, Y Tế, Sản Xuất...
    website: text('website'),

    contactPerson: text('contact_person'),
    contactPhone: text('contact_phone'),

    status: text('status').default('LEAD'), // LEAD, ACTIVE_CUSTOMER, CHURNED
    createdAt: timestamp('created_at').defaultNow(),
});

// --- RELATIONS ---
export const organizationsRelations = relations(organizations, ({ one }) => ({
    user: one(users, { fields: [organizations.userId], references: [users.id] }),
}));
