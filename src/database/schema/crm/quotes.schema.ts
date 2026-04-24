import {
    pgTable,
    serial,
    text,
    integer,
    numeric,
    timestamp,
    date,
    index,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { organizations } from './organizations.schema';
import { employees } from '../hrm/employees.schema';
import { leads } from './leads.schema';

/**
 * QUOTES — Báo giá
 *
 * Luồng status:
 *   DRAFT → SENT → ACCEPTED → REJECTED → EXPIRED
 *
 * Khi ACCEPTED → Có thể tạo Contract từ Quote này.
 * File PDF được gen và lưu link vào pdf_url.
 */
export const quotes = pgTable(
    'quotes',
    {
        id: serial('id').primaryKey(),

        organization_id: integer('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'restrict' }),

        // Lead liên quan (nullable)
        lead_id: integer('lead_id'),

        // Nhân viên tạo báo giá
        created_by_id: integer('created_by_id').references(() => employees.id, {
            onDelete: 'set null',
        }),

        quote_number: text('quote_number').notNull().unique(), // VD: BG-2026-001
        title: text('title').notNull(),

        // Trạng thái
        status: text('status').default('DRAFT').notNull(),
        // DRAFT | SENT | ACCEPTED | REJECTED | EXPIRED

        // Tổng tiền (tính từ quote_items, lưu lại để query nhanh)
        subtotal: numeric('subtotal', { precision: 15, scale: 2 }).default('0'),
        discount_percent: numeric('discount_percent', {
            precision: 5,
            scale: 2,
        }).default('0'),
        tax_percent: numeric('tax_percent', { precision: 5, scale: 2 }).default(
            '10',
        ), // VAT 10%
        total_amount: numeric('total_amount', {
            precision: 15,
            scale: 2,
        }).default('0'),
        currency: text('currency').default('VND'),

        // Hiệu lực báo giá
        valid_until: date('valid_until'),

        // File PDF đã xuất
        pdf_url: text('pdf_url'),
        google_drive_id: text('google_drive_id'),

        // Ghi chú cho khách hàng
        note: text('note'),

        sent_at: timestamp('sent_at', { withTimezone: true }),
        accepted_at: timestamp('accepted_at', { withTimezone: true }),

        created_at: timestamp('created_at').defaultNow().notNull(),
        updated_at: timestamp('updated_at').defaultNow().notNull(),
    },
    (table) => ({
        status_idx: index('idx_quotes_status').on(table.status),
        org_idx: index('idx_quotes_organization').on(table.organization_id),
    }),
);

/**
 * QUOTE_ITEMS — Các dòng hàng trong báo giá
 * Mỗi Quote có nhiều items (1-N)
 */
export const quoteItems = pgTable('quote_items', {
    id: serial('id').primaryKey(),

    quote_id: integer('quote_id')
        .notNull()
        .references(() => quotes.id, { onDelete: 'cascade' }),

    // Tên dịch vụ / sản phẩm
    description: text('description').notNull(),

    // Đơn vị tính (ngày, tháng, cái, gói...)
    unit: text('unit').default('gói'),

    quantity: numeric('quantity', { precision: 10, scale: 2 }).notNull(),
    unit_price: numeric('unit_price', { precision: 15, scale: 2 }).notNull(),

    // amount = quantity * unit_price (lưu sẵn, không tính lại khi đọc)
    amount: numeric('amount', { precision: 15, scale: 2 }).notNull(),

    // Thứ tự hiển thị trong PDF
    sort_order: integer('sort_order').default(0),

    note: text('note'),
});

// --- RELATIONS ---
export const quotesRelations = relations(quotes, ({ one, many }) => ({
    organization: one(organizations, {
        fields: [quotes.organization_id],
        references: [organizations.id],
    }),
    createdBy: one(employees, {
        fields: [quotes.created_by_id],
        references: [employees.id],
    }),
    items: many(quoteItems),
    lead: one(leads, {
        fields: [quotes.lead_id],
        references: [leads.id],
    }),
}));

export const quoteItemsRelations = relations(quoteItems, ({ one }) => ({
    quote: one(quotes, {
        fields: [quoteItems.quote_id],
        references: [quotes.id],
    }),
}));
