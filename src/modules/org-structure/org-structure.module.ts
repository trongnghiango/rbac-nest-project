import { Module } from '@nestjs/common';
import { OrgStructureController } from './infrastructure/controllers/org-structure.controller';
import { OrgStructureService } from './application/services/org-structure.service';
import { IOrgStructureRepository } from './domain/repositories/org-structure.repository';
import { DrizzleOrgStructureRepository } from './infrastructure/persistence/drizzle-org-structure.repository';

@Module({
    controllers: [OrgStructureController],
    providers: [
        OrgStructureService,
        {
            provide: IOrgStructureRepository,
            useClass: DrizzleOrgStructureRepository,
        },
    ],
    exports: [OrgStructureService], // Export nếu các module khác (như Employee) cần gọi
})
export class OrgStructureModule { }
