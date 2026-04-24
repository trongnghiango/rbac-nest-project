import {
    pgTable,
    serial,
    text,
    varchar,
    integer,
    numeric,
    timestamp,
    index,
    boolean,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { employees } from '../hrm/employees.schema';
import { organizations } from '../crm/organizations.schema';

/**
 * FINOTES — Phiếu Kế toán (Header)
 */
export const finotes = pgTable(
    'finotes',
    {
        id: serial('id').primaryKey(),
        code: varchar('code', { length: 50 }).notNull().unique(), // FN260106050
        type: varchar('type', { length: 20 }).default('INCOME').notNull(), // INCOME | EXPENSE
        
        source_org_id: integer('source_org_id').references(() => organizations.id, {
            onDelete: 'set null',
        }),

        requested_by_id: integer('requested_by_id')
            .notNull()
            .references(() => employees.id, { onDelete: 'restrict' }),

        reviewer_id: integer('reviewer_id').references(() => employees.id, {
            onDelete: 'set null',
        }),

        title: text('title').notNull(),
        total_amount: numeric('total_amount', { precision: 15, scale: 2 }).notNull(),
        total_vat: numeric('total_vat', { precision: 15, scale: 2 }).default('0'),
        currency: text('currency').default('VND'),
        category: text('category'), // Trả lại category để không break data cũ
        description: text('description'), // Trả lại description
        status: text('status').default('PENDING').notNull(), 

        deadline_at: timestamp('deadline_at', { withTimezone: true }).notNull(),
        paid_at: timestamp('paid_at', { withTimezone: true }),
        created_at: timestamp('created_at').defaultNow().notNull(),
        updated_at: timestamp('updated_at').defaultNow().notNull(),
    }
);

/**
 * FINOTE_ITEMS — Chi tiết từng dòng trong hóa đơn
 */
export const finoteItems = pgTable('finote_items', {
    id: serial('id').primaryKey(),
    finote_id: integer('finote_id').notNull().references(() => finotes.id, { onDelete: 'cascade' }),
    description: text('description').notNull(),
    amount: numeric('amount', { precision: 15, scale: 2 }).notNull(),
    vat_rate: integer('vat_rate').default(0),
    vat_amount: numeric('vat_amount', { precision: 15, scale: 2 }).default('0'),
    total_amount: numeric('total_amount', { precision: 15, scale: 2 }).notNull(),
});

/**
 * CASH_TRANSACTIONS — Sổ quỹ / Dòng tiền thực tế (CASH FLOW)
 */
export const cashTransactions = pgTable('cash_transactions', {
    id: serial('id').primaryKey(),
    type: varchar('type', { length: 10 }).notNull(), // IN | OUT
    amount: numeric('amount', { precision: 15, scale: 2 }).notNull(),
    transaction_date: timestamp('transaction_date', { withTimezone: true }).defaultNow().notNull(),
    payment_method: varchar('payment_method', { length: 50 }),
    bank_account: varchar('bank_account', { length: 100 }),
    transaction_ref: text('transaction_ref'),
    note: text('note'),
    recorded_by_id: integer('recorded_by_id').references(() => employees.id),
    status: varchar('status', { length: 20 }).default('COMPLETED'),
});

/**
 * FINOTE_PAYMENTS — Mapping giữa dòng tiền và hóa đơn
 */
export const finotePayments = pgTable('finote_payments', {
    id: serial('id').primaryKey(),
    finote_id: integer('finote_id').notNull().references(() => finotes.id),
    cash_transaction_id: integer('cash_transaction_id').notNull().references(() => cashTransactions.id),
    amount_mapped: numeric('amount_mapped', { precision: 15, scale: 2 }).notNull(),
    created_at: timestamp('created_at').defaultNow().notNull(),
});

/**
 * BILLING_TEMPLATES — Thu phí định kỳ
 */
export const billingTemplates = pgTable('billing_templates', {
    id: serial('id').primaryKey(),
    organization_id: integer('organization_id').notNull().references(() => organizations.id),
    title: text('title').notNull(),
    base_amount: numeric('base_amount', { precision: 15, scale: 2 }).notNull(),
    frequency: varchar('frequency', { length: 20 }).notNull(),
    next_billing_date: timestamp('next_billing_date').notNull(),
    is_active: boolean('is_active').default(true),
});

/**
 * FINOTE_ATTACHMENTS (Khôi phục)
 */
export const finoteAttachments = pgTable('finote_attachments', {
    id: serial('id').primaryKey(),
    finote_id: integer('finote_id')
        .notNull()
        .references(() => finotes.id, { onDelete: 'cascade' }),
    file_name: text('file_name').notNull(),
    google_drive_id: text('google_drive_id').notNull().unique(),
    web_view_link: text('web_view_link'),
    mime_type: text('mime_type'),
    file_size: integer('file_size'),
    uploaded_at: timestamp('uploaded_at').defaultNow().notNull(),
});

// --- RELATIONS ---
export const finotesRelations = relations(finotes, ({ one, many }) => ({
    requestedBy: one(employees, { fields: [finotes.requested_by_id], references: [employees.id], relationName: 'requested' }),
    items: many(finoteItems),
    payments: many(finotePayments),
    attachments: many(finoteAttachments),
    organization: one(organizations, { fields: [finotes.source_org_id], references: [organizations.id] }),
}));

export const finoteItemsRelations = relations(finoteItems, ({ one }) => ({
    finote: one(finotes, { fields: [finoteItems.finote_id], references: [finotes.id] }),
}));

export const cashTransactionsRelations = relations(cashTransactions, ({ many }) => ({
    mappings: many(finotePayments),
}));

export const finotePaymentsRelations = relations(finotePayments, ({ one }) => ({
    finote: one(finotes, { fields: [finotePayments.finote_id], references: [finotes.id] }),
    transaction: one(cashTransactions, { fields: [finotePayments.cash_transaction_id], references: [cashTransactions.id] }),
}));

export const finoteAttachmentsRelations = relations(finoteAttachments, ({ one }) => ({
    finote: one(finotes, { fields: [finoteAttachments.finote_id], references: [finotes.id] }),
}));
