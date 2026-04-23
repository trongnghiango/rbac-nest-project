// src/modules/accounting/application/strategies/target-resolver/expense-target.strategy.ts
import { Injectable } from '@nestjs/common';
import { ITargetResolverStrategy } from './target-resolver.interface';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { eq } from 'drizzle-orm';

@Injectable()
export class ExpenseTargetStrategy implements ITargetResolverStrategy {
    supportsType(): string {
        return 'EXPENSE';
    }

    async resolveTargetName(payload: any, db: NodePgDatabase<typeof schema>): Promise<string> {
        if (!payload.creatorId) return 'Hệ thống';

        const emp = await db.query.employees.findFirst({
            where: eq(schema.employees.id, payload.creatorId)
        });
        return emp ? emp.fullName : 'Nhân viên không xác định';
    }
}
