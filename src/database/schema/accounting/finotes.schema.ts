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
    pgEnum,
    bigint,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { employees } from '../hrm/employees.schema';
import { organizations } from '../crm/organizations.schema';

export const finoteStatusEnum = pgEnum('finote_status', ['PENDING', 'APPROVED', 'PAID', 'PARTIALLY_PAID', 'CANCELLED', 'REJECTED']);
export const finoteTypeEnum = pgEnum('finote_type', ['INCOME', 'EXPENSE']);
export const cashTransactionTypeEnum = pgEnum('cash_transaction_type', ['IN', 'OUT']);

/**
 * FINOTES — Phiếu Kế toán (Header)
 */
export const finotes = pgTable(
    'finotes',
    {
        id: serial('id').primaryKey(),
        code: varchar('code', { length: 50 }).notNull().unique(),
        type: finoteTypeEnum('type').default('INCOME').notNull(),
        
        sourceOrgId: bigint('source_org_id', { mode: 'number' })
            .references(() => organizations.id, { onDelete: 'set null' }),

        requestedById: integer('requested_by_id')
            .notNull()
            .references(() => employees.id, { onDelete: 'restrict' }),

        reviewerId: integer('reviewer_id')
            .references(() => employees.id, { onDelete: 'set null' }),

        title: text('title').notNull(),
        totalAmount: numeric('total_amount', { precision: 15, scale: 2 }).notNull(),
        totalVat: numeric('total_vat', { precision: 15, scale: 2 }).default('0'),
        currency: text('currency').default('VND'),
        category: text('category'),
        description: text('description'),
        status: finoteStatusEnum('status').default('PENDING').notNull(), 

        deadlineAt: timestamp('deadline_at', { withTimezone: true }).notNull(),
        paidAt: timestamp('paid_at', { withTimezone: true }),
        createdAt: timestamp('created_at').defaultNow().notNull(),
        updatedAt: timestamp('updated_at').defaultNow().notNull(),
    }
);

/**
 * FINOTE_ITEMS — Chi tiết từng dòng trong hóa đơn
 */
export const finoteItems = pgTable('finote_items', {
    id: serial('id').primaryKey(),
    finoteId: integer('finote_id')
        .notNull()
        .references(() => finotes.id, { onDelete: 'cascade' }),
    
    description: text('description').notNull(),
    amount: numeric('amount', { precision: 15, scale: 2 }).notNull(),
    vatRate: integer('vat_rate').default(0),
    vatAmount: numeric('vat_amount', { precision: 15, scale: 2 }).default('0'),
    totalAmount: numeric('total_amount', { precision: 15, scale: 2 }).notNull(),
});

/**
 * CASH_TRANSACTIONS — Sổ quỹ / Dòng tiền thực tế (CASH FLOW)
 */
export const cashTransactions = pgTable('cash_transactions', {
    id: serial('id').primaryKey(),
    type: cashTransactionTypeEnum('type').notNull(),
    amount: numeric('amount', { precision: 15, scale: 2 }).notNull(),
    transactionDate: timestamp('transaction_date', { withTimezone: true }).defaultNow().notNull(),
    paymentMethod: varchar('payment_method', { length: 50 }),
    bankAccount: varchar('bank_account', { length: 100 }),
    transactionRef: text('transaction_ref'),
    note: text('note'),
    recordedById: integer('recorded_by_id').references(() => employees.id),
    status: varchar('status', { length: 20 }).default('COMPLETED'),
});

/**
 * FINOTE_PAYMENTS — Mapping giữa dòng tiền và hóa đơn
 */
export const finotePayments = pgTable('finote_payments', {
    id: serial('id').primaryKey(),
    finoteId: integer('finote_id')
        .notNull()
        .references(() => finotes.id),
    
    cashTransactionId: integer('cash_transaction_id')
        .notNull()
        .references(() => cashTransactions.id),
    
    amountMapped: numeric('amount_mapped', { precision: 15, scale: 2 }).notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
});

/**
 * BILLING_TEMPLATES — Thu phí định kỳ
 */
export const billingTemplates = pgTable('billing_templates', {
    id: serial('id').primaryKey(),
    organizationId: bigint('organization_id', { mode: 'number' })
        .notNull()
        .references(() => organizations.id),
    
    title: text('title').notNull(),
    baseAmount: numeric('base_amount', { precision: 15, scale: 2 }).notNull(),
    frequency: varchar('frequency', { length: 20 }).notNull(),
    nextBillingDate: timestamp('next_billing_date').notNull(),
    isActive: boolean('is_active').default(true),
});

/**
 * FINOTE_ATTACHMENTS (Khôi phục)
 */
export const finoteAttachments = pgTable('finote_attachments', {
    id: serial('id').primaryKey(),
    finoteId: integer('finote_id')
        .notNull()
        .references(() => finotes.id, { onDelete: 'cascade' }),
    
    fileName: text('file_name').notNull(),
    googleDriveId: text('google_drive_id').notNull().unique(),
    webViewLink: text('web_view_link'),
    mimeType: text('mime_type'),
    fileSize: integer('file_size'),
    uploadedAt: timestamp('uploaded_at').defaultNow().notNull(),
});

// --- RELATIONS ---
export const finotesRelations = relations(finotes, ({ one, many }) => ({
    requestedBy: one(employees, { fields: [finotes.requestedById], references: [employees.id], relationName: 'requested' }),
    items: many(finoteItems),
    payments: many(finotePayments),
    attachments: many(finoteAttachments),
    organization: one(organizations, { fields: [finotes.sourceOrgId], references: [organizations.id] }),
}));

export const finoteItemsRelations = relations(finoteItems, ({ one }) => ({
    finote: one(finotes, { fields: [finoteItems.finoteId], references: [finotes.id] }),
}));

export const cashTransactionsRelations = relations(cashTransactions, ({ many }) => ({
    mappings: many(finotePayments),
}));

export const finotePaymentsRelations = relations(finotePayments, ({ one }) => ({
    finote: one(finotes, { fields: [finotePayments.finoteId], references: [finotes.id] }),
    transaction: one(cashTransactions, { fields: [finotePayments.cashTransactionId], references: [cashTransactions.id] }),
}));

export const finoteAttachmentsRelations = relations(finoteAttachments, ({ one }) => ({
    finote: one(finotes, { fields: [finoteAttachments.finoteId], references: [finotes.id] }),
}));
