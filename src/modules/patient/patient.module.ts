import { Module } from '@nestjs/common';
import { IClinicRepository } from '@modules/organization/domain/repositories/clinic.repository';
import { DrizzlePatientRepository } from '@modules/patient/infrastructure/persistence/repositories/drizzle-patient.repository';
import { IPatientRepository } from '@modules/patient/domain/repositories/patient.repository';
import { PatientService } from '@modules/patient/domain/services/patient.service';
import { PatientController } from '@modules/patient/infrastructure/controllers/patient.controller';

@Module({
  imports: [],
  controllers: [PatientController],
  providers: [
    // 👇 BẠN ĐANG THIẾU CỤC NÀY (Hoặc chưa define đúng):
    {
      provide: IPatientRepository, // Token (Symbol)
      useClass: DrizzlePatientRepository, // Class thực thi
    },
    PatientService,
  ],
  // 👇 Chỉ khi có ở trên 'providers' thì mới được phép nằm ở 'exports'
  exports: [IPatientRepository, PatientService],
})
export class PatientModule {}
