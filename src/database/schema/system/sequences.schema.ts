// src/database/schema/system/sequences.schema.ts
import { pgTable, varchar, integer, timestamp } from 'drizzle-orm/pg-core';

export const systemSequences = pgTable('system_sequences', {
    // prefix sẽ lưu dạng: 'FIN-INCOME-2026' hoặc 'EMP'
    prefix: varchar('prefix', { length: 50 }).primaryKey(),
    currentValue: integer('current_value').notNull().default(0),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});
