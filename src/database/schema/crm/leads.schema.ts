import {
    pgTable,
    serial,
    text,
    integer,
    numeric,
    timestamp,
    index,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { organizations } from './organizations.schema';
import { contacts } from './contacts.schema';
import { employees } from '../hrm/employees.schema';
import { contracts } from './contracts.schema';
import { quotes } from './quotes.schema';

/**
 * LEADS — Danh sách tiềm năng / Cơ hội bán hàng
 *
 * Luồng stage:
 *   NEW → CONSULTING → NEGOTIATING → WON → LOST
 *
 * Một Lead có thể chưa có Organization (cold lead chưa xác định công ty).
 * Khi chốt (WON) thì tạo Contract liên kết.
 */
export const leads = pgTable(
    'leads',
    {
        id: serial('id').primaryKey(),

        // Công ty liên quan (nullable — lead mới chưa xác định công ty)
        organization_id: integer('organization_id').references(
            () => organizations.id,
            { onDelete: 'set null' },
        ),
        // Thông tin liên hệ trực tiếp (khi chưa có Organization)
        contact_id: integer('contact_id').references(
            () => contacts.id,
            { onDelete: 'set null' }
        ),
        // Nhân viên Sales phụ trách
        assigned_to_id: integer('assigned_to_id').references(() => employees.id, {
            onDelete: 'set null',
        }),

        // Người tạo lead
        created_by_id: integer('created_by_id').references(() => employees.id, {
            onDelete: 'set null',
        }),

        title: text('title').notNull(),


        // Giai đoạn trong pipeline
        service_need: text('service_need'),
        stage: text('stage').default('UNCONSULTED').notNull(),
        // NEW | CONSULTING | NEGOTIATING | WON | LOST

        // Nguồn dẫn khách
        source: text('source'),
        // REFERRAL | WEBSITE | COLD_CALL | EVENT | SOCIAL | OTHER

        // Giá trị ước tính của deal
        estimated_value: numeric('estimated_value', { precision: 15, scale: 2 }),



        // Ghi chú nội bộ
        note: text('note'),

        // Thời gian chốt kỳ vọng
        expected_close_date: timestamp('expected_close_date', {
            withTimezone: true,
        }),

        // Thời gian thực sự đóng deal (WON hoặc LOST)
        closed_at: timestamp('closed_at', { withTimezone: true }),

        // Lý do thua (LOST)
        lost_reason: text('lost_reason'),

        created_at: timestamp('created_at').defaultNow().notNull(),
        updated_at: timestamp('updated_at').defaultNow().notNull(),
    },
    (table) => ({
        // Index cho các trường thường xuyên filter
        stage_idx: index('idx_leads_stage').on(table.stage),
        assigned_idx: index('idx_leads_assigned_to').on(table.assigned_to_id),
        org_idx: index('idx_leads_organization').on(table.organization_id),
        contact_idx: index('idx_leads_contact').on(table.contact_id),
    }),
);

// --- RELATIONS ---
export const leadsRelations = relations(leads, ({ one, many }) => ({
    organization: one(organizations, {
        fields: [leads.organization_id],
        references: [organizations.id],
    }),
    contact: one(contacts, {
        fields: [leads.contact_id],
        references: [contacts.id],
    }),
    assignedTo: one(employees, {
        fields: [leads.assigned_to_id],
        references: [employees.id],
        relationName: 'assignedLeads',
    }),
    createdBy: one(employees, {
        fields: [leads.created_by_id],
        references: [employees.id],
        relationName: 'createdLeads',
    }),
    contracts: many(contracts),
    quotes: many(quotes),
}));
