import { pgTable, serial, text, timestamp, bigint, jsonb, index } from 'drizzle-orm/pg-core';
import { organizations } from '../crm/organizations.schema';
import { users } from '../core/users.schema';

export const interactionNotes = pgTable(
    'interaction_notes',
    {
        id: serial('id').primaryKey(),
        organizationId: bigint('organization_id', { mode: 'number' })
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),
        
        createdById: bigint('created_by_id', { mode: 'number' })
            .references(() => users.id, { onDelete: 'set null' }),
        
        type: text('type').default('NOTE').notNull(), // e.g., 'NOTE', 'CALL', 'EMAIL', 'SYSTEM'
        content: text('content').notNull(),
        metadata: jsonb('metadata'),
        
        createdAt: timestamp('created_at').defaultNow().notNull(),
        updatedAt: timestamp('updated_at').defaultNow().notNull(),
    },
    (table) => ({
        org_idx: index('idx_interaction_notes_org').on(table.organizationId),
        created_at_idx: index('idx_interaction_notes_created').on(table.createdAt),
    }),
);
