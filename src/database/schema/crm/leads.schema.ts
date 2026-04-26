import { pgTable, serial, text, timestamp, bigint, integer, index, pgEnum, jsonb } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { organizations } from './organizations.schema';
import { users } from '../core/users.schema';
import { positions } from '../hrm/org-structure.schema';

export const leadStatusEnum = pgEnum('lead_status', ['NEW', 'CONTACTED', 'QUALIFIED', 'PROPOSAL', 'NEGOTIATION', 'WON', 'LOST', 'ARCHIVED']);
export const leadSourceEnum = pgEnum('lead_source', ['WEBSITE', 'REFERRAL', 'ADVERTISING', 'EVENT', 'OFFLINE', 'OTHER']);

export const leads = pgTable(
    'leads',
    {
        id: serial('id').primaryKey(),
        organizationId: bigint('organization_id', { mode: 'number' })
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),
        
        assignedPositionId: integer('assigned_position_id')
            .references(() => positions.id, { onDelete: 'set null' }),
        
        title: text('title').notNull(),
        status: leadStatusEnum('status').default('NEW').notNull(),
        source: leadSourceEnum('source').default('OTHER').notNull(),
        
        expectedValue: bigint('expected_value', { mode: 'number' }),
        confidence: integer('confidence').default(50), // 0-100
        
        contactName: text('contact_name'),
        contactEmail: text('contact_email'),
        contactPhone: text('contact_phone'),
        
        lastInteractionAt: timestamp('last_interaction_at'),
        nextFollowUpAt: timestamp('next_follow_up_at'),
        
        metadata: jsonb('metadata'),
        createdAt: timestamp('created_at').defaultNow().notNull(),
        updatedAt: timestamp('updated_at').defaultNow().notNull(),
    },
    (table) => ({
        org_idx: index('idx_leads_org').on(table.organizationId),
        status_idx: index('idx_leads_status').on(table.status),
    }),
);

export const leadsRelations = relations(leads, ({ one }) => ({
    organization: one(organizations, {
        fields: [leads.organizationId],
        references: [organizations.id],
    }),
    assignedPosition: one(positions, {
        fields: [leads.assignedPositionId],
        references: [positions.id],
    }),
}));
