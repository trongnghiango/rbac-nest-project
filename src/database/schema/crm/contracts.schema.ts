import {
    pgTable,
    serial,
    text,
    integer,
    numeric,
    timestamp,
    date,
    index,
    pgEnum,
    jsonb,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { organizations } from './organizations.schema';
import { employees } from '../hrm/employees.schema';
import { leads } from './leads.schema';

export const contractStatusEnum = pgEnum('contract_status', ['DRAFT', 'PENDING_SIGN', 'ACTIVE', 'EXPIRING_SOON', 'EXPIRED', 'CANCELLED']);
export const contractTypeEnum = pgEnum('contract_type', ['RETAINER', 'ONE_OFF']);

export const contracts = pgTable(
    'contracts',
    {
        id: serial('id').primaryKey(),

        organization_id: integer('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'restrict' }),

        lead_id: integer('lead_id').references(() => leads.id, { onDelete: 'set null' }),

        managed_by_id: integer('managed_by_id').references(() => employees.id, {
            onDelete: 'set null',
        }),

        contract_number: text('contract_number').notNull().unique(),
        title: text('title').notNull(),
        description: text('description'),

        contract_type: contractTypeEnum('contract_type').default('RETAINER').notNull(),
        status: contractStatusEnum('status').default('PENDING_SIGN').notNull(),

        value: numeric('value', { precision: 15, scale: 2 }),
        currency: text('currency').default('VND'),

        start_date: date('start_date'),
        end_date: date('end_date'),
        signed_at: timestamp('signed_at', { withTimezone: true }),

        file_url: text('file_url'),
        google_drive_id: text('google_drive_id'),
        note: text('note'),
        metadata: jsonb('metadata'),

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
