import { Module } from '@nestjs/common';
import { IDentistRepository } from '@modules/medical-staff/domain/repositories/dentist.repository';
import { DrizzleDentistRepository } from '@modules/medical-staff/infrastructure/persistence/repositories/drizzle-dentist.repository';
import { DentistService } from '@modules/medical-staff/domain/services/dentist.service';
import { DentistController } from '@modules/medical-staff/infrastructure/controllers/dentist.controller';

@Module({
  imports: [],
  controllers: [DentistController],
  providers: [
    { provide: IDentistRepository, useClass: DrizzleDentistRepository },
    DentistService,
  ],
  // 👇 QUAN TRỌNG: Phải export thì module khác mới dùng được
  exports: [IDentistRepository, DentistService],
})
export class MedicalStaffModule {}
