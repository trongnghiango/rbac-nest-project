import { pgTable, serial, text, timestamp, bigint, boolean, index, pgEnum, jsonb } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from '../core/users.schema';
import { leads } from './leads.schema';
import { contracts } from './contracts.schema';
import { quotes } from './quotes.schema';
import { contacts } from './contacts.schema';
import { serviceAssignments } from './service-assignments.schema';
import { orgUnits } from '../hrm/org-structure.schema';
import { employees } from '../hrm/employees.schema';

export const organizationStatusEnum = pgEnum('organization_status', ['PROSPECT', 'ACTIVE', 'INACTIVE', 'CHURNED']);
export const organizationTypeEnum = pgEnum('organization_type', ['INDIVIDUAL', 'ENTERPRISE']);

export const organizations = pgTable(
    'organizations',
    {
        id: serial('id').primaryKey(),
        userId: bigint('user_id', { mode: 'number' }).unique().references(() => users.id, { onDelete: 'set null' }),

        isInternal: boolean('is_internal').default(false).notNull(),

        companyName: text('company_name').notNull(),
        taxCode: text('tax_code').unique(),

        type: organizationTypeEnum('type').default('INDIVIDUAL').notNull(),
        industry: text('industry'),
        website: text('website'),
        address: text('address'),

        status: organizationStatusEnum('status').default('PROSPECT').notNull(),
        note: text('note'),
        metadata: jsonb('metadata'),
        createdAt: timestamp('created_at').defaultNow().notNull(),
        updatedAt: timestamp('updated_at').defaultNow().notNull(),
    },
    (table) => ({
        status_idx: index('idx_organizations_status').on(table.status),
        internal_idx: index('idx_organizations_internal').on(table.isInternal),
    }),
);

export const organizationsRelations = relations(organizations, ({ one, many }) => ({
    user: one(users, {
        fields: [organizations.userId],
        references: [users.id],
    }),
    contacts: many(contacts),
    leads: many(leads),
    contracts: many(contracts),
    quotes: many(quotes),
    serviceAssignments: many(serviceAssignments),
    orgUnits: many(orgUnits),
    employees: many(employees),
}));