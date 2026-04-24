import {
    pgTable,
    serial,
    text,
    integer,
    timestamp,
    index,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { employees } from '../hrm/employees.schema';

/**
 * ATTACHMENTS — File đính kèm dùng chung (Polymorphic)
 *
 * Dùng Polymorphic Association thay vì tạo bảng riêng cho từng module.
 * entity_type + entity_id xác định file thuộc về đối tượng nào.
 *
 * Ví dụ:
 *   entity_type = 'contract', entity_id = 5  → File của Contract ID 5
 *   entity_type = 'employee', entity_id = 12 → File của Employee ID 12
 *   entity_type = 'quote',    entity_id = 3  → File của Quote ID 3
 *
 * Supported entity types:
 *   contract | quote | employee | lead | finote | performance_review
 */
export const attachments = pgTable(
    'attachments',
    {
        id: serial('id').primaryKey(),

        // Ai upload
        uploaded_by_id: integer('uploaded_by_id').references(() => employees.id, {
            onDelete: 'set null',
        }),

        // Polymorphic FK
        entity_type: text('entity_type').notNull(),
        entity_id: integer('entity_id').notNull(),

        // Thông tin file
        file_name: text('file_name').notNull(),
        original_name: text('original_name').notNull(), // Tên gốc trước khi rename

        // Google Drive
        google_drive_id: text('google_drive_id').notNull().unique(),
        web_view_link: text('web_view_link'),   // Mở xem trong Google Docs/Sheets
        download_link: text('download_link'),   // Download trực tiếp

        // Metadata
        mime_type: text('mime_type'),
        file_size: integer('file_size'),        // Bytes
        folder_path: text('folder_path'),       // Path trong Drive (VD: /STAX/Contracts/2026)

        created_at: timestamp('created_at').defaultNow().notNull(),
    },
    (table) => ({
        // Index kép — query "Tất cả file của Contract ID 5"
        entity_idx: index('idx_attachments_entity').on(
            table.entity_type,
            table.entity_id,
        ),
        drive_idx: index('idx_attachments_drive_id').on(table.google_drive_id),
    }),
);

// --- RELATIONS ---
export const attachmentsRelations = relations(attachments, ({ one }) => ({
    uploadedBy: one(employees, {
        fields: [attachments.uploaded_by_id],
        references: [employees.id],
    }),
}));
