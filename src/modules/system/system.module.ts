import { Module } from '@nestjs/common';
import { SystemController } from './infrastructure/controllers/system.controller';
import { RbacModule } from '@modules/rbac/rbac.module';
import { UserModule } from '@modules/user/user.module';
import { LookupService } from './application/services/lookup.service';
import { BootstrapService } from './application/services/bootstrap.service';

@Module({
    imports: [
        RbacModule,
        UserModule
    ],
    controllers: [SystemController],
    providers: [
        LookupService,
        BootstrapService
    ],
    exports: [
        LookupService,
        BootstrapService
    ]
})
export class SystemModule {}
