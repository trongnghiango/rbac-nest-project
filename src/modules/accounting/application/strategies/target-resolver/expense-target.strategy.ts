// src/modules/accounting/application/strategies/target-resolver/expense-target.strategy.ts
import { Inject, Injectable } from '@nestjs/common';
import { ITargetResolverStrategy } from './target-resolver.interface';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { eq } from 'drizzle-orm';
import { IEmployeeRepository } from '@modules/employee/domain/repositories/employee.repository';

@Injectable()
export class ExpenseTargetStrategy implements ITargetResolverStrategy {
    constructor(
        @Inject(IEmployeeRepository) private readonly employeeRepo: IEmployeeRepository
    ) { }

    supportsType(): string { return 'EXPENSE'; }

    async resolveTargetName(payload: any): Promise<string> {
        if (!payload.creatorId) return 'Hệ thống';

        // Dùng Repo thay vì db.query
        const emp = await this.employeeRepo.findById(payload.creatorId);
        return emp ? emp.fullName : 'Nhân viên không xác định';
    }
}
