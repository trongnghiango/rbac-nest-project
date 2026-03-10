import { Module } from '@nestjs/common';
import { UserModule } from '../user/user.module';
import { RbacModule } from '../rbac/rbac.module'; 
import { DatabaseSeeder } from './seeders/database.seeder';
import { TestController } from './controllers/test.controller';

@Module({
  imports: [UserModule, RbacModule],
  controllers: [TestController],
  providers: [DatabaseSeeder],
})
export class TestModule {} 
