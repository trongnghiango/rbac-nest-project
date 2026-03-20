import { Module } from '@nestjs/common';
import { OrgStructureController } from './infrastructure/controllers/org-structure.controller';
import { OrgStructureService } from './application/services/org-structure.service';
import { IOrgStructureRepository } from './domain/repositories/org-structure.repository';
import { DrizzleOrgStructureRepository } from './infrastructure/persistence/drizzle-org-structure.repository';
import { CompanyImportController } from './infrastructure/controllers/company-import.controller';
import { CompanyImportService } from './application/services/company-import.service';
import { RbacModule } from '@modules/rbac/rbac.module';

@Module({
    imports: [RbacModule],
    controllers: [OrgStructureController, CompanyImportController],
    providers: [
        OrgStructureService,
        CompanyImportService,
        {
            provide: IOrgStructureRepository,
            useClass: DrizzleOrgStructureRepository,
        },
    ],
    exports: [OrgStructureService, IOrgStructureRepository, CompanyImportService], // Export nếu các module khác (như Employee) cần gọi
})
export class OrgStructureModule { }
