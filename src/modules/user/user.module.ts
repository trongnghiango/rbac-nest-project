import { Module } from '@nestjs/common';
import { UserService } from './application/services/user.service';
import { UserController } from './infrastructure/controllers/user.controller';
import { DrizzleUserRepository } from './infrastructure/persistence/drizzle-user.repository';
// FIX IMPORT
import { IUserRepository } from './domain/repositories/user.repository';
import { UserImportService } from './application/services/user-import.service';
import { UserImportController } from './infrastructure/controllers/user-import.controller';
import { RbacModule } from '@modules/rbac/rbac.module';
import { UserUniquenessChecker } from './domain/services/user-uniqueness.checker';
import { EmployeeAccountRequestedListener } from './application/listeners/employee-account-requested.listener';
import { IUserAccountService } from './domain/ports/user-account.service.port';
import { UserAccountService } from './application/services/user-account.service';

@Module({
  imports: [RbacModule],
  controllers: [UserController, UserImportController],
  providers: [
    UserService,
    UserImportService,
    UserUniquenessChecker,
    EmployeeAccountRequestedListener, 
    {
      provide: IUserAccountService,
      useClass: UserAccountService,
    },
    {
      provide: IUserRepository, // FIX: Dùng Symbol
      useClass: DrizzleUserRepository,
    },
  ],
  exports: [UserService, IUserAccountService, IUserRepository, UserUniquenessChecker], // FIX: Export Symbol
})
export class UserModule { }
