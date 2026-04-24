import { Module } from '@nestjs/common';
import { LeadWorkflowService } from './application/services/lead-workflow.service';
import { LeadIntakeService } from './application/services/lead-intake.service';
import { LeadController } from './infrastructure/controllers/lead.controller';
import { RbacModule } from '@modules/rbac/rbac.module';
import { ILeadRepository } from './domain/repositories/lead.repository';
import { DrizzleLeadRepository } from './infrastructure/persistence/drizzle-lead.repository';
import { IOrganizationRepository } from './domain/repositories/organization.repository';
import { DrizzleOrganizationRepository } from './infrastructure/persistence/drizzle-organization.repository';
import { IContractRepository } from './domain/repositories/contract.repository';
import { DrizzleContractRepository } from './infrastructure/persistence/drizzle-contract.repository';
import { IServiceAssignmentRepository } from './domain/repositories/service-assignment.repository';
import { DrizzleServiceAssignmentRepository } from './infrastructure/persistence/drizzle-assignment.repository';
import { IContactRepository } from './domain/repositories/contact.repository';
import { DrizzleContactRepository } from './infrastructure/persistence/drizzle-contact.repository';

@Module({
    imports: [RbacModule],
    controllers: [LeadController],
    providers: [
        LeadWorkflowService,
        LeadIntakeService,
        { provide: ILeadRepository, useClass: DrizzleLeadRepository },
        { provide: IOrganizationRepository, useClass: DrizzleOrganizationRepository },
        { provide: IContactRepository, useClass: DrizzleContactRepository },
        { provide: IContractRepository, useClass: DrizzleContractRepository },
        { provide: IServiceAssignmentRepository, useClass: DrizzleServiceAssignmentRepository },
    ],
    exports: [LeadWorkflowService, LeadIntakeService, IOrganizationRepository, IContactRepository],
})
export class CrmModule { }