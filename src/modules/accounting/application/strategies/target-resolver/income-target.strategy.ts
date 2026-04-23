// src/modules/accounting/application/strategies/target-resolver/income-target.strategy.ts
import { Injectable } from '@nestjs/common';
import { ITargetResolverStrategy } from './target-resolver.interface';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { eq } from 'drizzle-orm';

@Injectable()
export class IncomeTargetStrategy implements ITargetResolverStrategy {
    supportsType(): string {
        return 'INCOME';
    }

    async resolveTargetName(payload: any, db: NodePgDatabase<typeof schema>): Promise<string> {
        if (!payload.orgId) return 'Khách hàng vãng lai';

        const org = await db.query.organizations.findFirst({
            where: eq(schema.organizations.id, payload.orgId)
        });
        return org ? org.company_name : 'Không xác định';
    }
}
