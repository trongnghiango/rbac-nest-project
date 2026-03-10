import { Module } from '@nestjs/common';
import { IClinicRepository } from '@modules/organization/domain/repositories/clinic.repository';
import { DrizzleClinicRepository } from '@modules/organization/infrastructure/persistence/repositories/drizzle-clinic.repository';
import { ClinicService } from '@modules/organization/domain/services/clinic.service';
import { ClinicController } from '@modules/organization/infrastructure/controllers/clinic.controller';

@Module({
  imports: [],
  controllers: [ClinicController],
  providers: [
    { provide: IClinicRepository, useClass: DrizzleClinicRepository },
    ClinicService,
  ],
  // 👇 QUAN TRỌNG: Phải export thì module khác mới dùng được
  exports: [IClinicRepository, ClinicService],
})
export class OrganizationModule {}
