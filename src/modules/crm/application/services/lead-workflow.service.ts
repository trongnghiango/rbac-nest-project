// src/modules/crm/application/services/lead-workflow.service.ts
import { Injectable, Inject, BadRequestException, NotFoundException } from '@nestjs/common';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { ILeadRepository } from '@modules/crm/domain/repositories/lead.repository';
import { IOrganizationRepository } from '@modules/crm/domain/repositories/organization.repository';
import { IContractRepository } from '@modules/crm/domain/repositories/contract.repository';
import { IServiceAssignmentRepository } from '@modules/crm/domain/repositories/service-assignment.repository';
import { CloseLeadCommand } from '../dtos/close-lead.dto';
import { Contract, ContractType, ContractStatus } from '../../domain/entities/contract.entity';

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
            // 1. Tải Entities (Repository đã dùng Mapper để trả về Domain Entity)
            const lead = await this.leadRepo.findById(command.leadId);
            if (!lead) throw new NotFoundException('Không tìm thấy Lead');

            const org = await this.orgRepo.findById(lead.organizationId);
            if (!org) throw new NotFoundException('Không tìm thấy Tổ chức liên quan');

            // 2. Thực thi nghiệp vụ bên trong Entity (Vấn đề 2: Rich Domain Model)
            // Logic kiểm tra isWon, organizationId... nằm trong hàm closeAsWon() của Lead
            lead.closeAsWon();

            // Logic nâng cấp lên Enterprise, cập nhật TaxCode nằm trong hàm onboard() của Organization
            org.activate();
            if (command.newCompanyName || command.taxCode) {
                org.applyEnterpriseInfo(command.newCompanyName, command.taxCode);
            }

            // 3. Lưu thay đổi trạng thái Entities
            await this.leadRepo.save(lead);
            await this.orgRepo.save(org);

            // 4. Tạo Hợp đồng mới (Dùng Entity Constructor)
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

            // 5. Xử lý gán Team
            if (command.teamAssignments?.length) {
                await this.assignmentRepo.replaceByOrganization(org.id, command.teamAssignments);
            }

            // 6. Bắn Event (Vấn đề 5: Sử dụng mã nghiệp vụ hoặc ID sạch)
            await this.eventBus.publish({
                aggregateId: org.id.toString(),
                occurredAt: new Date(),
                payload: {
                    event: 'CLIENT_ONBOARDED',
                    orgId: org.id,
                    contractId: savedContract.id,
                    contractNumber: savedContract.contractNumber
                }
            });

            return {
                success: true,
                message: 'Chốt hợp đồng thành công!',
                contractId: savedContract.id
            };
        });
    }
}
