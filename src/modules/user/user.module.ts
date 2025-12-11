import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserService } from './application/services/user.service';
import { TypeOrmUserRepository } from './infrastructure/persistence/typeorm-user.repository';
import { UserController } from './infrastructure/controllers/user.controller';
import { UserOrmEntity } from './infrastructure/persistence/entities/user.orm-entity';

@Module({
  imports: [TypeOrmModule.forFeature([UserOrmEntity])], // Import ORM Entity here, NOT Domain Entity
  controllers: [UserController],
  providers: [
    UserService,
    {
      provide: 'IUserRepository',
      useClass: TypeOrmUserRepository,
    },
  ],
  exports: [UserService, 'IUserRepository'],
})
export class UserModule {}
