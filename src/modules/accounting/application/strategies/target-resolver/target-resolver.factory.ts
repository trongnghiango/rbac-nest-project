// src/modules/accounting/application/strategies/target-resolver/target-resolver.factory.ts
import { Injectable } from '@nestjs/common';
import { ITargetResolverStrategy } from './target-resolver.interface';
import { IncomeTargetStrategy } from './income-target.strategy';
import { ExpenseTargetStrategy } from './expense-target.strategy';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';

@Injectable()
export class TargetResolverFactory {
    private strategies = new Map<string, ITargetResolverStrategy>();

    constructor(
        incomeStrategy: IncomeTargetStrategy,
        expenseStrategy: ExpenseTargetStrategy,
    ) {
        // Đăng ký các strategy vào Map (Từ điển)
        this.registerStrategy(incomeStrategy);
        this.registerStrategy(expenseStrategy);
    }

    private registerStrategy(strategy: ITargetResolverStrategy) {
        this.strategies.set(strategy.supportsType(), strategy);
    }

    /**
     * Hàm cốt lõi: Không còn IF-ELSE. Chỉ việc lookup trong Map O(1).
     */
    async resolve(type: string, payload: any, db: NodePgDatabase<typeof schema>): Promise<string> {
        const strategy = this.strategies.get(type);

        if (!strategy) {
            return 'Đối tượng chưa xác định'; // Fallback nếu có type mới mà chưa viết class
        }

        return await strategy.resolveTargetName(payload, db);
    }
}
