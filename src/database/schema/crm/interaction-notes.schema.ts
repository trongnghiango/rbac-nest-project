import {
    pgTable,
    serial,
    text,
    integer,
    timestamp,
    index,
    jsonb,
    varchar,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { organizations } from './organizations.schema';
import { users } from '../core/users.schema';

export const interactionNotes = pgTable(
    'interaction_notes',
    {
        id: serial('id').primaryKey(),
        organization_id: integer('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),
        
        created_by_id: integer('created_by_id')
            .references(() => users.id, { onDelete: 'set null' }),
        
        // Loại tương tác: CALL, MEETING, EMAIL, NOTE
        type: varchar('type', { length: 20 }).default('NOTE').notNull(),
        
        content: text('content').notNull(),
        
        metadata: jsonb('metadata'),
        
        created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
        updated_at: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
    },
    (table) => ({
        org_idx: index('idx_interaction_org').on(table.organization_id),
        actor_idx: index('idx_interaction_actor').on(table.created_by_id),
        created_at_idx: index('idx_interaction_created').on(table.created_at),
    }),
);

export const interactionNotesRelations = relations(interactionNotes, ({ one }) => ({
    organization: one(organizations, {
        fields: [interactionNotes.organization_id],
        references: [organizations.id],
    }),
    creator: one(users, {
        fields: [interactionNotes.created_by_id],
        references: [users.id],
    }),
}));
