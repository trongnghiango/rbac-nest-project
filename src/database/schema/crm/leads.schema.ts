import {
    pgTable,
    serial,
    text,
    integer,
    numeric,
    timestamp,
    index,
    pgEnum,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { organizations } from './organizations.schema';
import { contacts } from './contacts.schema';
import { employees } from '../hrm/employees.schema';
import { contracts } from './contracts.schema';
import { quotes } from './quotes.schema';

export const leadStageEnum = pgEnum('lead_stage', ['NEW', 'CONSULTING', 'NEGOTIATING', 'WON', 'LOST']);
export const leadSourceEnum = pgEnum('lead_source', ['REFERRAL', 'WEBSITE', 'COLD_CALL', 'EVENT', 'SOCIAL', 'DIRECT', 'ZALO', 'OTHER']);

export const leads = pgTable(
    'leads',
    {
        id: serial('id').primaryKey(),
        organization_id: integer('organization_id').references(
            () => organizations.id,
            { onDelete: 'set null' },
        ),
        contact_id: integer('contact_id').references(
            () => contacts.id,
            { onDelete: 'set null' }
        ),
        assigned_to_id: integer('assigned_to_id').references(() => employees.id, {
            onDelete: 'set null',
        }),
        created_by_id: integer('created_by_id').references(() => employees.id, {
            onDelete: 'set null',
        }),

        title: text('title').notNull(),
        service_need: text('service_need'),
        stage: leadStageEnum('stage').default('NEW').notNull(),
        source: leadSourceEnum('source').default('DIRECT'),

        estimated_value: numeric('estimated_value', { precision: 15, scale: 2 }),
        note: text('note'),
        expected_close_date: timestamp('expected_close_date', { withTimezone: true }),
        closed_at: timestamp('closed_at', { withTimezone: true }),
        lost_reason: text('lost_reason'),

        created_at: timestamp('created_at').defaultNow().notNull(),
        updated_at: timestamp('updated_at').defaultNow().notNull(),
    },
    (table) => ({
        stage_idx: index('idx_leads_stage').on(table.stage),
        assigned_idx: index('idx_leads_assigned_to').on(table.assigned_to_id),
        org_idx: index('idx_leads_organization').on(table.organization_id),
        contact_idx: index('idx_leads_contact').on(table.contact_id),
    }),
);

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
