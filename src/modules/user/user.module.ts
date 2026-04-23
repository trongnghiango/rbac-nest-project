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

@Module({
  imports: [RbacModule],
  controllers: [UserController, UserImportController],
  providers: [
    UserService,
    UserImportService,
    UserUniquenessChecker,
    EmployeeAccountRequestedListener, // Đăng ký Listener
    {
      provide: IUserRepository, // FIX: Dùng Symbol
      useClass: DrizzleUserRepository,
    },
  ],
  exports: [UserService, IUserRepository, UserUniquenessChecker], // FIX: Export Symbol
})
export class UserModule { }
