import { pgTable, serial, integer, text, timestamp, boolean, index, jsonb, bigint } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { organizations } from './organizations.schema';
import { users } from '../core/users.schema';

export const contacts = pgTable('contacts', {
    id: serial('id').primaryKey(),

    // NẾU LÀ B2B: Điền ID của Organization. 
    // NẾU LÀ B2C (Khách lẻ mua E-commerce): Để NULL.
    organizationId: bigint('organization_id', { mode: 'number' })
        .references(() => organizations.id, { onDelete: 'set null' }),

    // Link với User account nếu khách lẻ tự tạo tài khoản
    userId: bigint('user_id', { mode: 'number' })
        .references(() => users.id, { onDelete: 'set null' }),

    fullName: text('full_name').notNull(),
    email: text('email').unique(),
    phone: text('phone'),
    address: text('address'),

    jobTitle: text('job_title'), // Ví dụ: Giám đốc, Kế toán trưởng
    isPrimary: boolean('is_primary').default(false), // Người liên hệ chính của công ty?
    metadata: jsonb('metadata'),

    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, (table) => ({
    org_idx: index('idx_contacts_org').on(table.organizationId),
    email_idx: index('idx_contacts_email').on(table.email),
}));

export const contactsRelations = relations(contacts, ({ one }) => ({
    organization: one(organizations, {
        fields: [contacts.organizationId],
        references: [organizations.id],
    }),
    user: one(users, {
        fields: [contacts.userId],
        references: [users.id],
    }),
}));
