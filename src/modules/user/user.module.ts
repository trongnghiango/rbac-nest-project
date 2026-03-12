import { Module } from '@nestjs/common';
import { UserService } from './application/services/user.service';
import { UserController } from './infrastructure/controllers/user.controller';
import { DrizzleUserRepository } from './infrastructure/persistence/drizzle-user.repository';
// FIX IMPORT
import { IUserRepository } from './domain/repositories/user.repository';
import { UserImportService } from './application/services/user-import.service';
import { UserImportController } from './infrastructure/controllers/user-import.controller';
import { RbacModule } from '@modules/rbac/rbac.module';

@Module({
  imports: [RbacModule],
  controllers: [UserController, UserImportController],
  providers: [
    UserService,
    UserImportService,
    {
      provide: IUserRepository, // FIX: Dùng Symbol
      useClass: DrizzleUserRepository,
    },
  ],
  exports: [UserService, IUserRepository], // FIX: Export Symbol
})
export class UserModule { }
