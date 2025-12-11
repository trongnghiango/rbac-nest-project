import { Module, OnModuleInit } from '@nestjs/common';
import { UserModule } from '../user/user.module';
import { RbacModule } from '../rbac/rbac.module'; // Import RBAC
import { DatabaseSeeder } from './seeders/database.seeder';
import { TestController } from './controllers/test.controller';

@Module({
  imports: [
    UserModule,
    RbacModule, // <--- QUAN TRỌNG: Cần thiết cho PermissionGuard
  ],
  controllers: [TestController],
  providers: [DatabaseSeeder],
})
export class TestModule implements OnModuleInit {
  constructor(private s: DatabaseSeeder) {}
  async onModuleInit() {
    await this.s.onModuleInit();
  }
}
