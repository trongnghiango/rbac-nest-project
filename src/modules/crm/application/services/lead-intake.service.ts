// src/modules/crm/application/services/lead-intake.service.ts
import { Injectable, Inject, Logger } from '@nestjs/common';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { ILeadRepository } from '../../domain/repositories/lead.repository';
import { IOrganizationRepository } from '../../domain/repositories/organization.repository';
import { IContactRepository } from '../../domain/repositories/contact.repository';
import { Lead } from '../../domain/entities/lead.entity';
import { Organization, OrganizationStatus, OrganizationType } from '../../domain/entities/organization.entity';
import { Contact } from '../../domain/entities/contact.entity';
import { LeadStage } from '../../domain/enums/lead-stage.enum';

export interface IntelligentIntakeDto {
    fullName: string;
    phone: string;
    email?: string;
    serviceDemand: string;
    source?: string;
    notes?: string;
    assignedToId?: number;
}

@Injectable()
export class LeadIntakeService {
    private readonly logger = new Logger(LeadIntakeService.name);

    constructor(
        @Inject(ITransactionManager) private readonly txManager: ITransactionManager,
        @Inject(ILeadRepository) private readonly leadRepo: ILeadRepository,
        @Inject(IOrganizationRepository) private readonly orgRepo: IOrganizationRepository,
        @Inject(IContactRepository) private readonly contactRepo: IContactRepository,
    ) {}

    async intelligentIntake(dto: IntelligentIntakeDto) {
        const trackingId = `INTAKE-${Date.now()}`;
        this.logger.debug(`[${trackingId}] Bắt đầu quy trình Tiếp nhận Lead thông minh cho: ${dto.fullName}`);

        return this.txManager.runInTransaction(async () => {
            let organizationId: number;
            let contactId: number | undefined;

            this.logger.debug(`[${trackingId}] Bước 1: Kiểm tra khách hàng hiện hữu qua SĐT: ${dto.phone}`);
            const existingContact = await this.contactRepo.findByPhone(dto.phone);
            let isNewOrgCreated = false;

            if (existingContact && existingContact.organizationId) {
                organizationId = existingContact.organizationId;
                contactId = existingContact.id;
                this.logger.debug(`[${trackingId}] Kết quả: Tìm thấy khách hàng cũ (OrgId: ${organizationId}). Tái sử dụng hồ sơ.`);
            } else {
                this.logger.debug(`[${trackingId}] Kết quả: Cần tạo Organization mới (Khách mới hoặc khách lẻ chưa có hồ sơ cty).`);
                isNewOrgCreated = true;

                const newOrg = new Organization({
                    companyName: dto.fullName, 
                    status: OrganizationStatus.PROSPECT,
                    type: OrganizationType.INDIVIDUAL,
                    taxCode: null,
                    isInternal: false,
                });
                const savedOrg = await this.orgRepo.save(newOrg);
                organizationId = savedOrg.id!;
                this.logger.debug(`[${trackingId}] -> Đã tạo Organization mới (ID: ${organizationId})`);

                if (existingContact) {
                    // Cập nhật Contact cũ để gắn vào Org mới
                    contactId = existingContact.id;
                    // Note: Here we assume our entity or mapper handles updating. 
                    // In real DDD, we might have a method contact.assignToOrganization(id)
                    const updatedContact = new Contact({
                        ...existingContact,
                        organizationId: organizationId,
                    });
                    await this.contactRepo.save(updatedContact);
                    this.logger.debug(`[${trackingId}] -> Đã cập nhật Contact cũ (ID: ${contactId}) vào Org mới.`);
                } else {
                    const newContact = new Contact({
                        organizationId: organizationId,
                        fullName: dto.fullName,
                        phone: dto.phone,
                        email: dto.email,
                        isMain: true,
                    });
                    const savedContact = await this.contactRepo.save(newContact);
                    contactId = savedContact.id;
                    this.logger.debug(`[${trackingId}] -> Đã tạo Contact liên hệ chính (ID: ${contactId})`);
                }
            }

            this.logger.debug(`[${trackingId}] Bước 2: Khởi tạo thực thể Lead cho nhu cầu: ${dto.serviceDemand}`);
            const newLead = new Lead({
                organizationId: organizationId,
                contactId: contactId,
                title: dto.serviceDemand,
                serviceNeed: dto.serviceDemand,
                source: dto.source || 'DIRECT',
                stage: LeadStage.NEW,
                assignedToId: dto.assignedToId,
                note: dto.notes,
            });

            const savedLead = await this.leadRepo.save(newLead);
            this.logger.log(`[${trackingId}] HOÀN TẤT: Đã tiếp nhận Lead thành công (ID: ${savedLead.id}).`);

            return {
                leadId: savedLead.id,
                organizationId: organizationId,
                isNewCustomer: isNewOrgCreated
            };
        });
    }
}
