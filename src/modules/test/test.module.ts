import { Module } from '@nestjs/common';
import { UserModule } from '../user/user.module';
import { RbacModule } from '../rbac/rbac.module';
import { DatabaseSeeder } from './seeders/database.seeder';
import { VerifyAuditLogScript } from './application/scripts/verify-audit-log';
import { TestController } from './controllers/test.controller';
import { OrgStructureModule } from '../org-structure/org-structure.module';

@Module({
  imports: [UserModule, RbacModule, OrgStructureModule],
  controllers: [TestController],
  providers: [DatabaseSeeder, VerifyAuditLogScript],
})
export class TestModule { } 
