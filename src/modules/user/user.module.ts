import { Module } from '@nestjs/common';
import { UserService } from './application/services/user.service';
import { UserController } from './infrastructure/controllers/user.controller';
import { DrizzleUserRepository } from './infrastructure/persistence/drizzle-user.repository';

@Module({
  imports: [], // Không cần TypeOrmModule nữa
  controllers: [UserController],
  providers: [
    UserService,
    {
      provide: 'IUserRepository',
      useClass: DrizzleUserRepository,
    },
  ],
  exports: [UserService, 'IUserRepository'],
})
export class UserModule {}
