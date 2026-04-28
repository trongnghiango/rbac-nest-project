// src/modules/crm/application/services/lead-workflow.service.ts
import { Injectable, Inject, BadRequestException, NotFoundException, Logger } from '@nestjs/common';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { ILeadRepository } from '@modules/crm/domain/repositories/lead.repository';
import { IOrganizationRepository } from '@modules/crm/domain/repositories/organization.repository';
import { IContractRepository } from '@modules/crm/domain/repositories/contract.repository';
import { IServiceAssignmentRepository } from '@modules/crm/domain/repositories/service-assignment.repository';
import { CloseLeadCommand } from '../dtos/close-lead.dto';
import { Contract, ContractType, ContractStatus } from '../../domain/entities/contract.entity';

import { ClientOnboardedEvent } from '../../onboarding/domain/events/client-onboarded.event';

@Injectable()
export class LeadWorkflowService {
    private readonly logger = new Logger(LeadWorkflowService.name);

    constructor(
        @Inject(ITransactionManager) private readonly txManager: ITransactionManager,
        @Inject(IEventBus) private readonly eventBus: IEventBus,
        @Inject(ILeadRepository) private readonly leadRepo: ILeadRepository,
        @Inject(IOrganizationRepository) private readonly orgRepo: IOrganizationRepository,
        @Inject(IContractRepository) private readonly contractRepo: IContractRepository,
        @Inject(IServiceAssignmentRepository) private readonly assignmentRepo: IServiceAssignmentRepository,
    ) { }

    async closeLeadAsWon(command: CloseLeadCommand) {
        const trackingId = `WON-${command.leadId}-${Date.now()}`;
        this.logger.log(`[${trackingId}] Bắt đầu quy trình CHỐT HỢP ĐỒNG (Close Won) cho Lead: ${command.leadId}`);

        return this.txManager.runInTransaction(async () => {
            this.logger.debug(`[${trackingId}] 1. Tải thực thể Lead và Organization...`);
            const lead = await this.leadRepo.findById(command.leadId);
            if (!lead) throw new NotFoundException('Không tìm thấy Lead');

            const org = await this.orgRepo.findById(lead.organizationId);
            if (!org) throw new NotFoundException('Không tìm thấy Tổ chức liên quan');

            this.logger.debug(`[${trackingId}] 2. Thực thi logic chuyển đổi trạng thái...`);
            lead.closeAsWon();

            org.activate();
            if (command.newCompanyName || command.taxCode) {
                org.applyEnterpriseInfo(command.newCompanyName, command.taxCode);
                this.logger.debug(`[${trackingId}] -> Đã nâng cấp Organization thành ENTERPRISE: ${command.newCompanyName}`);
            }

            await this.leadRepo.save(lead);
            await this.orgRepo.save(org);

            this.logger.debug(`[${trackingId}] 3. Khởi tạo Hợp đồng mới...`);
            const contractType = command.serviceType.includes('RETAINER')
                ? ContractType.RETAINER
                : ContractType.ONE_OFF;

            const contract = new Contract({
                id: undefined as any,
                organizationId: org.id,
                leadId: lead.id!,
                contractNumber: command.contractNumber,
                title: command.serviceType,
                contractType: contractType,
                status: ContractStatus.ACTIVE,
                value: command.feeAmount,
                currency: 'VND',
                signedAt: new Date(),
            });

            const savedContract = await this.contractRepo.create(contract);
            this.logger.log(`[${trackingId}] -> Đã tạo Hợp đồng số: ${savedContract.contractNumber}`);

            if (command.teamAssignments?.length) {
                this.logger.debug(`[${trackingId}] 4. Gán đội ngũ phục vụ (Team Assignments)...`);
                await this.assignmentRepo.replaceByOrganization(org.id, command.teamAssignments);
            }

            this.logger.debug(`[${trackingId}] 5. Phát hành sự kiện CLIENT_ONBOARDED.`);
            await this.eventBus.publish(new ClientOnboardedEvent(
                org.id.toString(),
                new Date(),
                {
                    orgId: org.id,
                    contractId: savedContract.id,
                    contractNumber: savedContract.contractNumber
                }
            ));

            this.logger.log(`[${trackingId}] HOÀN TẤT: Chốt Lead thành công (ContractId: ${savedContract.id}).`);

            return {
                success: true,
                message: 'Chốt hợp đồng thành công!',
                contractId: savedContract.id
            };
        });
    }
}
