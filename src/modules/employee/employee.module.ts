import { Module } from '@nestjs/common';
import { OrgStructureModule } from '../org-structure/org-structure.module'; // Import module hàng xóm

import { EmployeeController } from './infrastructure/controllers/employee.controller';
import { EmployeeService } from './application/services/employee.service';
import { IEmployeeRepository } from './domain/repositories/employee.repository';
import { DrizzleEmployeeRepository } from './infrastructure/persistence/drizzle-employee.repository';
import { RbacModule } from '@modules/rbac/rbac.module';
import { CoreEmployeeImportedListener } from './application/listeners/core-employee-imported.listener';

@Module({
    imports: [
        OrgStructureModule, // Cần import để EmployeeService dùng được IOrgStructureRepository
        RbacModule,
    ],
    controllers: [
        EmployeeController,
    ],
    providers: [
        EmployeeService,
        CoreEmployeeImportedListener,
        {
            provide: IEmployeeRepository,
            useClass: DrizzleEmployeeRepository, // Binding Interface với Implementation
        },
    ],
    exports: [EmployeeService, IEmployeeRepository], // Export nếu sau này module Payroll cần mượn
})
export class EmployeeModule { }
