import { Injectable } from '@nestjs/common';
import { LeadStage } from '@modules/crm/domain/enums/lead-stage.enum';
import { FinoteType, FinoteStatus } from '@modules/accounting/domain/entities/finote.entity';
import { ContractStatus } from '@modules/crm/domain/entities/contract.entity';
import { OrganizationStatus, OrganizationType } from '@modules/crm/domain/entities/organization.entity';

@Injectable()
export class LookupService {
  /**
   * Trả về toàn bộ danh mục Enums cho Frontend
   * Tập trung kiến thức về các danh mục tại đây thay vì Controller
   */
  getCommonLookups() {
    return {
      leadStages: Object.values(LeadStage),
      finoteTypes: Object.values(FinoteType),
      finoteStatuses: Object.values(FinoteStatus),
      contractStatuses: Object.values(ContractStatus),
      organizationStatuses: Object.values(OrganizationStatus),
      organizationTypes: Object.values(OrganizationType),
    };
  }
}
