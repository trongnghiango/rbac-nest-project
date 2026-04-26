// src/modules/crm/infrastructure/persistence/drizzle-assignment.repository.ts
import { Injectable, Inject } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { IServiceAssignmentRepository } from '../../domain/repositories/service-assignment.repository';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';

@Injectable()
export class DrizzleServiceAssignmentRepository extends DrizzleBaseRepository implements IServiceAssignmentRepository {
    constructor(@Inject(DRIZZLE) db: NodePgDatabase<typeof schema>) {
        super(db);
    }

    async replaceByOrganization(orgId: number, assignments: any[]): Promise<void> {
        const db = this.getDb();

        // 1. Xóa cũ
        await db.delete(schema.serviceAssignments)
            .where(eq(schema.serviceAssignments.organizationId, orgId));

        // 2. Chèn mới
        if (assignments.length > 0) {
            const dataToInsert = assignments.map(a => ({
                organizationId: orgId,
                employeeId: a.employeeId,
                role: a.role,
                assignedAt: new Date(),
            }));
            await db.insert(schema.serviceAssignments).values(dataToInsert as any);
        }
    }
}
