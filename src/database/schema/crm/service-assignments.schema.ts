// src/database/schema/crm/service-assignments.schema.ts
import { pgTable, serial, integer, text, timestamp, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { organizations } from './organizations.schema';
import { employees } from '../hrm/employees.schema';

export const serviceAssignments = pgTable('service_assignments', {
    id: serial('id').primaryKey(),
    organizationId: integer('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    employeeId: integer('employee_id').notNull().references(() => employees.id, { onDelete: 'cascade' }),

    role: text('role').notNull(), // LEADER, CHUYEN_VIEN_B1, TRO_LY...

    assignedAt: timestamp('assigned_at').defaultNow().notNull(),
}, (table) => ({
    org_idx: index('idx_service_assignments_org').on(table.organizationId),
}));

export const serviceAssignmentsRelations = relations(serviceAssignments, ({ one }) => ({
    organization: one(organizations, {
        fields: [serviceAssignments.organizationId],
        references: [organizations.id],
    }),
    employee: one(employees, {
        fields: [serviceAssignments.employeeId],
        references: [employees.id],
    }),
}));
