import { Module, OnModuleInit, Inject } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MulterModule } from '@nestjs/platform-express';
import { diskStorage } from 'multer';

import { DentalController } from './infrastructure/controllers/dental.controller';
import dentalConfig from '@config/dental.config';

// Modules vệ tinh
import { OrganizationModule } from '../organization/organization.module';
import { PatientModule } from '../patient/patient.module';
import { MedicalStaffModule } from '../medical-staff/medical-staff.module';
// ✅ Import Core Module vừa sửa ở Bước 1
import { DentalTreatmentModule } from '../dental-treatment/dental-treatment.module';

// Use Cases & Queries riêng của module này (nếu chưa chuyển sang Core)
import { UploadCaseUseCase } from '../dental-treatment/application/use-cases/upload-case.use-case';
import { ProcessMovementDataUseCase } from '../dental-treatment/application/use-cases/process-movement-data.use-case';
import { GetCaseModelsQuery } from '../dental-treatment/application/queries/get-case-models.query';

// Infrastructure riêng của module này (Workers, Gateway)
import { PiscinaProvider } from '../dental-treatment/infrastructure/workers/piscina.provider';
import { DentalGateway } from '../dental-treatment/infrastructure/gateways/dental.gateway';
import { IDentalWorker } from '../dental-treatment/domain/ports/dental-worker.port';
import { PiscinaDentalWorker } from '../dental-treatment/infrastructure/adapters/piscina-worker.adapter';
import { IDentalStorage } from '../dental-treatment/domain/ports/dental-storage.port';

@Module({
  imports: [
    ConfigModule.forFeature(dentalConfig),

    // ✅ Import module Core: Tự động có Repo, Query, Storage từ exports của nó
    DentalTreatmentModule,

    OrganizationModule,
    PatientModule,
    MedicalStaffModule,

    MulterModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (config: ConfigService) => ({
        storage: diskStorage({
          destination: (req, file, cb) => {
            const uploadDir = config.get<string>('dental.uploadDir') || 'uploads/dental/temp';
            cb(null, uploadDir);
          },
          filename: (req, file, cb) => {
            cb(null, `${Date.now()}-${file.originalname}`);
          },
        }),
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [DentalController],
  providers: [

  ],
  exports: [],
})
export class DentalModule implements OnModuleInit {
  constructor(
    // Inject được vì DentalTreatmentModule đã export IDentalStorage
    @Inject(IDentalStorage) private readonly dentalStorage: IDentalStorage,
  ) { }

  onModuleInit() {
    this.dentalStorage.ensureDirectories();
  }
}

