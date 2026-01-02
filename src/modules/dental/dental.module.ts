import { Module, OnModuleInit, Inject } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MulterModule } from '@nestjs/platform-express';
import { diskStorage } from 'multer';

import { DentalController } from './infrastructure/controllers/dental.controller';

// --- IMPORT TỪ CÁC MODULE MỚI ---
import { OrganizationModule } from '../organization/organization.module';
import { PatientModule } from '../patient/patient.module';
import { MedicalStaffModule } from '../medical-staff/medical-staff.module';

// --- IMPORT USE CASE ---
import { UploadCaseUseCase } from '../dental-treatment/application/use-cases/upload-case.use-case';

// --- IMPORT INTERFACES (PORTS) TỪ MODULE DENTAL-TREATMENT ---
import { IOrthoRepository } from '../dental-treatment/domain/repositories/ortho.repository';
import { IDentalStorage } from '../dental-treatment/domain/ports/dental-storage.port';
import { IDentalWorker } from '../dental-treatment/domain/ports/dental-worker.port';

// --- IMPORT IMPLEMENTATIONS (ADAPTERS) TỪ MODULE DENTAL-TREATMENT ---
// Lưu ý: Tên class trong file repositories mới có thể vẫn là DrizzleOrthoRepository (do copy sang)
import { DrizzleOrthoRepository } from '../dental-treatment/infrastructure/persistence/repositories/drizzle-cases.repository';
import { FileSystemDentalStorage } from '../dental-treatment/infrastructure/adapters/fs-dental-storage.adapter';
import { PiscinaDentalWorker } from '../dental-treatment/infrastructure/adapters/piscina-worker.adapter';
import { PiscinaProvider } from '../dental-treatment/infrastructure/workers/piscina.provider';
import { DentalGateway } from '../dental-treatment/infrastructure/gateways/dental.gateway';

import dentalConfig from '@config/dental.config';
import { GetCaseModelsQuery } from '@modules/dental-treatment/application/queries/get-case-models.query';
import { GetPatientHistoryQuery } from '@modules/dental-treatment/application/queries/get-patient-history.query';
import { GetCaseDetailsQuery } from '@modules/dental-treatment/application/queries/get-case-details.query';
import { ProcessMovementDataUseCase } from '@modules/dental-treatment/application/use-cases/process-movement-data.use-case';

@Module({
  imports: [
    ConfigModule.forFeature(dentalConfig),
    // Import các module vệ tinh
    OrganizationModule,
    PatientModule,
    MedicalStaffModule,

    MulterModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (config: ConfigService) => ({
        storage: diskStorage({
          destination: (req, file, cb) => {
            const uploadDir =
              config.get<string>('dental.uploadDir') || 'uploads/dental/temp';
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
    // 1. Use Case & Services
    UploadCaseUseCase,
    ProcessMovementDataUseCase,
    GetPatientHistoryQuery,
    GetCaseDetailsQuery,
    GetCaseModelsQuery,
    // 2. Hạ tầng (Infrastructure Providers)
    DentalGateway,
    PiscinaProvider,

    // 3. BINDING PORTS -> ADAPTERS (Đây là phần bạn bị thiếu)
    {
      provide: IOrthoRepository, // Khi ai đó xin IOrthoRepository
      useClass: DrizzleOrthoRepository, // Thì đưa cho họ class này (lấy từ dental-treatment)
    },
    {
      provide: IDentalStorage,
      useClass: FileSystemDentalStorage, // Lấy từ dental-treatment
    },
    {
      provide: IDentalWorker,
      useClass: PiscinaDentalWorker, // Lấy từ dental-treatment
    },
  ],
  exports: [UploadCaseUseCase, ProcessMovementDataUseCase],
})
export class DentalModule implements OnModuleInit {
  constructor(
    @Inject(IDentalStorage) private readonly dentalStorage: IDentalStorage,
  ) {}

  onModuleInit() {
    this.dentalStorage.ensureDirectories();
  }
}
