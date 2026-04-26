import { pgTable, serial, text, timestamp, bigint, date, pgEnum, jsonb, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { organizations } from './organizations.schema';
import { leads } from './leads.schema';

export const contractStatusEnum = pgEnum('contract_status', ['DRAFT', 'PENDING', 'ACTIVE', 'EXPIRED', 'TERMINATED']);
export const contractTypeEnum = pgEnum('contract_type', ['ONE_OFF', 'RETAINER', 'SUBSCRIPTION']);

export const contracts = pgTable(
    'contracts',
    {
        id: serial('id').primaryKey(),
        organizationId: bigint('organization_id', { mode: 'number' })
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),
        
        leadId: bigint('lead_id', { mode: 'number' })
            .references(() => leads.id, { onDelete: 'set null' }),

        contractNumber: text('contract_number').notNull().unique(),
        title: text('title').notNull(),
        status: contractStatusEnum('status').default('DRAFT').notNull(),
        type: contractTypeEnum('type').default('ONE_OFF').notNull(),
        
        value: bigint('value', { mode: 'number' }).notNull(),
        currency: text('currency').default('VND').notNull(),
        
        signedAt: timestamp('signed_at'),
        startAt: timestamp('start_at'),
        endAt: timestamp('end_at'),
        
        metadata: jsonb('metadata'),
        createdAt: timestamp('created_at').defaultNow().notNull(),
        updatedAt: timestamp('updated_at').defaultNow().notNull(),
    },
    (table) => ({
        org_idx: index('idx_contracts_org').on(table.organizationId),
        num_idx: index('idx_contracts_num').on(table.contractNumber),
    }),
);

export const contractsRelations = relations(contracts, ({ one }) => ({
    organization: one(organizations, {
        fields: [contracts.organizationId],
        references: [organizations.id],
    }),
    lead: one(leads, {
        fields: [contracts.leadId],
        references: [leads.id],
    }),
}));
