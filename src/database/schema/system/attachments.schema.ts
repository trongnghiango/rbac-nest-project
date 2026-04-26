import { pgTable, serial, integer, text, timestamp, index, bigint } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { employees } from '../hrm/employees.schema';

export const attachments = pgTable('attachments', {
    id: serial('id').primaryKey(),

    uploadedById: integer('uploaded_by_id').references(() => employees.id, {
        onDelete: 'set null',
    }),

    // Polymorphic link
    entityType: text('entity_type').notNull(), // contract, quote, employee, lead, finote, performance_review
    entityId: integer('entity_id').notNull(),

    fileName: text('file_name').notNull(),
    originalName: text('original_name').notNull(),
    googleDriveId: text('google_drive_id').notNull().unique(),
    webViewLink: text('web_view_link'),
    downloadLink: text('download_link'),
    mimeType: text('mime_type'),
    fileSize: integer('file_size'),
    folderPath: text('folder_path'),

    createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
    entity_idx: index('idx_attachments_entity').on(table.entityType, table.entityId),
    drive_idx: index('idx_attachments_drive_id').on(table.googleDriveId),
}));

export const attachmentsRelations = relations(attachments, ({ one }) => ({
    uploader: one(employees, {
        fields: [attachments.uploadedById],
        references: [employees.id],
    }),
}));
