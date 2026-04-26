import { Test, TestingModule } from '@nestjs/testing';
import { LeadWorkflowService } from './lead-workflow.service';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { ILeadRepository } from '@modules/crm/domain/repositories/lead.repository';
import { IOrganizationRepository } from '@modules/crm/domain/repositories/organization.repository';
import { IContractRepository } from '@modules/crm/domain/repositories/contract.repository';
import { IServiceAssignmentRepository } from '@modules/crm/domain/repositories/service-assignment.repository';
import { AUDIT_LOG_PORT } from '@core/shared/application/ports/audit-log.port';
import { CloseLeadCommand } from '../dtos/close-lead.dto';

describe('LeadWorkflowService', () => {
    let service: LeadWorkflowService;
    let mockAuditLog: any;
    let mockLeadRepo: any;
    let mockOrgRepo: any;
    let mockContractRepo: any;

    beforeEach(async () => {
        mockAuditLog = {
            log: jest.fn().mockResolvedValue(undefined),
        };
        mockLeadRepo = {
            findById: jest.fn().mockResolvedValue({ 
                id: 1, 
                organizationId: 1, 
                closeAsWon: jest.fn() 
            }),
            save: jest.fn().mockResolvedValue(undefined),
        };
        mockOrgRepo = {
            findById: jest.fn().mockResolvedValue({ 
                id: 1, 
                activate: jest.fn(), 
                applyEnterpriseInfo: jest.fn() 
            }),
            save: jest.fn().mockResolvedValue(undefined),
        };
        mockContractRepo = {
            create: jest.fn().mockResolvedValue({ id: 99, contractNumber: 'CT-001' }),
        };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                LeadWorkflowService,
                { provide: ITransactionManager, useValue: { runInTransaction: jest.fn(cb => cb()) } },
                { provide: IEventBus, useValue: { publish: jest.fn().mockResolvedValue(undefined) } },
                { provide: ILeadRepository, useValue: mockLeadRepo },
                { provide: IOrganizationRepository, useValue: mockOrgRepo },
                { provide: IContractRepository, useValue: mockContractRepo },
                { provide: IServiceAssignmentRepository, useValue: { replaceByOrganization: jest.fn().mockResolvedValue(undefined) } },
                { provide: AUDIT_LOG_PORT, useValue: mockAuditLog },
            ],
        }).compile();

        service = module.get<LeadWorkflowService>(LeadWorkflowService);
    });

    it('should log audit event when lead is won', async () => {
        const command: CloseLeadCommand = {
            leadId: 1,
            contractNumber: 'CT-001',
            feeAmount: 1000,
            serviceType: 'RETAINER',
            actorId: 42,
            actorName: 'Test Sales',
        };

        await service.closeLeadAsWon(command);

        expect(mockAuditLog.log).toHaveBeenCalledWith(expect.objectContaining({
            action: 'LEAD.CLOSE_WON',
            resource: 'leads',
            resource_id: '1',
            actor_id: 42,
            actor_name: 'Test Sales',
        }));
    });
});
