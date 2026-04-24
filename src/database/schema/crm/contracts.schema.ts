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
 * CONTRACTS — Hợp đồng khách hàng
 *
 * Luồng status:
 *   DRAFT → ACTIVE → EXPIRED → CANCELLED
 *
 * Cronjob chạy hàng ngày:
 *   Tìm các contract có end_date - NOW() <= 7 ngày
 *   → Đổi status = 'EXPIRING_SOON' hoặc bắn Notification
 */
export const contracts = pgTable(
    'contracts',
    {
        id: serial('id').primaryKey(),

        organization_id: integer('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'restrict' }),

        // Lead dẫn đến hợp đồng này (nullable — có thể tạo thẳng không qua lead)
        lead_id: integer('lead_id'),

        // Nhân viên phụ trách / ký kết
        managed_by_id: integer('managed_by_id').references(() => employees.id, {
            onDelete: 'set null',
        }),

        contract_number: text('contract_number').notNull().unique(), // VD: HD-2026-001
        title: text('title').notNull(),
        description: text('description'),

        // Loai HD
        contract_type: text('contract_type').default('RETAINER').notNull(),
        // Trạng thái hợp đồng
        status: text('status').default('PENDING_SIGN').notNull(),
        // DRAFT | ACTIVE | EXPIRING_SOON | EXPIRED | CANCELLED

        // Giá trị hợp đồng
        value: numeric('value', { precision: 15, scale: 2 }),
        currency: text('currency').default('VND'),

        // Thời hạn
        start_date: date('start_date'),
        end_date: date('end_date'),   // Cronjob theo dõi trường này
        signed_at: timestamp('signed_at', { withTimezone: true }),

        // File đính kèm (Link Google Drive)
        file_url: text('file_url'),
        google_drive_id: text('google_drive_id'),

        // Ghi chú
        note: text('note'),

        created_at: timestamp('created_at').defaultNow().notNull(),
        updated_at: timestamp('updated_at').defaultNow().notNull(),
    },
    (table) => ({
        status_idx: index('idx_contracts_status').on(table.status),
        type_idx: index('idx_contracts_type').on(table.contract_type),
        end_date_idx: index('idx_contracts_end_date').on(table.end_date),
        org_idx: index('idx_contracts_organization').on(table.organization_id),
    }),
);

// --- RELATIONS ---
export const contractsRelations = relations(contracts, ({ one }) => ({
    organization: one(organizations, {
        fields: [contracts.organization_id],
        references: [organizations.id],
    }),
    managedBy: one(employees, {
        fields: [contracts.managed_by_id],
        references: [employees.id],
    }),
    lead: one(leads, {
        fields: [contracts.lead_id],
        references: [leads.id],
    }),
}));
