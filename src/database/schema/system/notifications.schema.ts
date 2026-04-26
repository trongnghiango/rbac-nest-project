import {
    pgTable,
    serial,
    text,
    timestamp,
    integer,
    boolean,
} from 'drizzle-orm/pg-core';

export const notifications = pgTable('notifications', {
    id: serial('id').primaryKey(),
    userId: integer('user_id').notNull(),
    type: text('type').notNull(), // EMAIL, SMS
    subject: text('subject').notNull(),
    content: text('content').notNull(),
    status: text('status').notNull(), // PENDING, SENT
    sentAt: timestamp('sent_at'),
    createdAt: timestamp('created_at').defaultNow(),
});
