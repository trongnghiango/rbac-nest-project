// src/database/schema/crm/contacts.schema.ts
import { pgTable, serial, integer, text, timestamp, boolean, index, jsonb } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { organizations } from './organizations.schema';
import { users } from '../core/users.schema';

export const contacts = pgTable('contacts', {
    id: serial('id').primaryKey(),

    // NẾU LÀ B2B: Điền ID của Organization. 
    // NẾU LÀ B2C (Khách lẻ mua E-commerce): Để NULL.
    organization_id: integer('organization_id').references(() => organizations.id, { onDelete: 'set null' }),

    // Link với User account nếu khách lẻ tự tạo tài khoản
    user_id: integer('user_id').references(() => users.id, { onDelete: 'set null' }),

    full_name: text('full_name').notNull(),
    email: text('email').unique(),
    phone: text('phone'),
    address: text('address'),

    job_title: text('job_title'), // Ví dụ: Giám đốc, Kế toán trưởng
    is_primary: boolean('is_primary').default(false), // Người liên hệ chính của công ty?
    metadata: jsonb('metadata'),

    created_at: timestamp('created_at').defaultNow().notNull(),
    updated_at: timestamp('updated_at').defaultNow().notNull(),
}, (table) => ({
    org_idx: index('idx_contacts_org').on(table.organization_id),
    email_idx: index('idx_contacts_email').on(table.email),
}));

export const contactsRelations = relations(contacts, ({ one }) => ({
    organization: one(organizations, {
        fields: [contacts.organization_id],
        references: [organizations.id],
    }),
    user: one(users, {
        fields: [contacts.user_id],
        references: [users.id],
    }),
}));
