import { Module } from '@nestjs/common';
import { SystemController } from './infrastructure/controllers/system.controller';
import { RbacModule } from '@modules/rbac/rbac.module';
import { UserModule } from '@modules/user/user.module';

@Module({
    imports: [
        RbacModule,
        UserModule
    ],
    controllers: [SystemController],
    providers: [],
    exports: []
})
export class SystemModule {}
