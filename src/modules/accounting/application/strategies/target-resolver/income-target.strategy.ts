// src/modules/accounting/application/strategies/target-resolver/income-target.strategy.ts
import { Inject, Injectable } from '@nestjs/common';
import { ITargetResolverStrategy } from './target-resolver.interface';
import { IOrganizationRepository } from '@modules/crm/domain/repositories/organization.repository';

@Injectable()
export class IncomeTargetStrategy implements ITargetResolverStrategy {
    constructor(
        @Inject(IOrganizationRepository) private readonly orgRepo: IOrganizationRepository
    ) { }

    supportsType(): string { return 'INCOME'; }

    async resolveTargetName(payload: any): Promise<string> {
        if (!payload.orgId) return 'Khách hàng vãng lai';

        // Dùng Repo thay vì db.query
        const org = await this.orgRepo.findById(payload.orgId);
        return org ? org.companyName : 'Không xác định';
    }
}

