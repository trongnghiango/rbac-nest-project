// src/modules/crm/application/services/lead-workflow.service.ts
import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { ILeadRepository } from '@modules/crm/domain/repositories/lead.repository';
import { IOrganizationRepository } from '@modules/crm/domain/repositories/organization.repository';
import { IContractRepository } from '@modules/crm/domain/repositories/contract.repository';
import { IServiceAssignmentRepository } from '@modules/crm/domain/repositories/service-assignment.repository';
import { CloseLeadCommand } from '../dtos/close-lead.dto';


@Injectable()
export class LeadWorkflowService {
    constructor(
        @Inject(ITransactionManager) private readonly txManager: ITransactionManager,
        @Inject(IEventBus) private readonly eventBus: IEventBus,
        @Inject(ILeadRepository) private readonly leadRepo: ILeadRepository,
        @Inject(IOrganizationRepository) private readonly orgRepo: IOrganizationRepository,
        @Inject(IContractRepository) private readonly contractRepo: IContractRepository,
        @Inject(IServiceAssignmentRepository) private readonly assignmentRepo: IServiceAssignmentRepository,
    ) { }

    async closeLeadAsWon(command: CloseLeadCommand) {
        return this.txManager.runInTransaction(async () => {
            // BỎ DÒNG: const dbTx = tx as ... (Vì không còn tx)

            const lead = await this.leadRepo.findById(command.leadId);
            if (!lead) throw new BadRequestException('Không tìm thấy Lead');
            if (lead.isWon()) throw new BadRequestException('Lead này đã được chốt Hợp đồng trước đó!');
            if (!lead.organizationId) throw new BadRequestException('Lead này chưa được gắn với Tổ chức nào!');

            // Dùng Repository (nó sẽ tự lấy tx từ ALS)
            await this.leadRepo.updateStage(lead.id, 'WON');

            const orgUpdateData: any = { status: 'ACTIVE', updated_at: new Date() };
            if (command.newCompanyName) orgUpdateData.company_name = command.newCompanyName;
            if (command.taxCode) {
                orgUpdateData.tax_code = command.taxCode;
                orgUpdateData.type = 'ENTERPRISE';
            }
            await this.orgRepo.update(lead.organizationId, orgUpdateData);

            // SỬA LỖI 'any' TRONG TERNARY:
            // Thay vì: contractType: condition ? any : any
            // Ta dùng ép kiểu cụ thể hoặc giá trị thực tế
            const contractType = command.serviceType.includes('RETAINER') ? 'RETAINER' : 'ONE_OFF';

            const newContract = await this.contractRepo.create({
                organizationId: lead.organizationId, // Dùng camelCase của Entity
                leadId: lead.id,
                contractNumber: command.contractNumber,
                value: command.feeAmount,
                title: command.serviceType,
                contractType: contractType as any, // Ép kiểu về enum
                status: 'ACTIVE',
                signedAt: new Date(),
                currency: 'VND'
            } as any);

            if (command.teamAssignments && command.teamAssignments.length > 0) {
                await this.assignmentRepo.replaceByOrganization(lead.organizationId, command.teamAssignments);
            }

            await this.eventBus.publish({
                aggregateId: lead.organizationId.toString(),
                occurredAt: new Date(),
                payload: {
                    event: 'CLIENT_ONBOARDED',
                    orgId: lead.organizationId,
                    contractId: newContract.id
                }
            });

            return {
                success: true,
                message: 'Chốt hợp đồng thành công!',
                contractId: newContract.id
            };
        });
    }
}
