import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

// 1. Import Modules Vệ Tinh (Để có ClinicService, PatientService, DentistService)
import { UserModule } from '../user/user.module';
import { OrganizationModule } from '../organization/organization.module';   // ✅ Cung cấp ClinicService
import { PatientModule } from '../patient/patient.module';             // ✅ Cung cấp PatientService
import { MedicalStaffModule } from '../medical-staff/medical-staff.module'; // ✅ Cung cấp DentistService

// 2. Interfaces & Repositories
import { IOrthoRepository } from './domain/repositories/ortho.repository';
import { DrizzleOrthoRepository } from './infrastructure/persistence/repositories/drizzle-cases.repository';
import { IDentalStorage } from './domain/ports/dental-storage.port';
import { FileSystemDentalStorage } from './infrastructure/adapters/fs-dental-storage.adapter';

// 3. Use Cases & Queries
import { UploadCaseUseCase } from './application/use-cases/upload-case.use-case';
import { GetCaseDetailsQuery } from './application/queries/get-case-details.query';
import { GetPatientHistoryQuery } from './application/queries/get-patient-history.query';
import { GetCaseModelsQuery } from './application/queries/get-case-models.query';
import { ProcessMovementDataUseCase } from './application/use-cases/process-movement-data.use-case';

// 4. Infrastructure (Chatbot, Worker, Gateway)
import { DentalTreatmentChatbot } from './infrastructure/chatbot/dental-treatment.chatbot';
import { UploadAlignerScene } from './infrastructure/chatbot/scenes/upload-aligner.scene';
import { PiscinaProvider } from './infrastructure/workers/piscina.provider'; // ✅ Cung cấp PISCINA_POOL
import { DentalGateway } from './infrastructure/gateways/dental.gateway';     // ✅ Cung cấp DentalGateway
import { IDentalWorker } from './domain/ports/dental-worker.port';
import { PiscinaDentalWorker } from './infrastructure/adapters/piscina-worker.adapter';

@Module({
  imports: [
    ConfigModule,       // Cần cho ConfigService
    UserModule,         // Cần cho Auth Guard
    OrganizationModule, // ✅ FIX LỖI: Cung cấp ClinicService
    PatientModule,      // ✅ FIX LỖI: Cung cấp PatientService
    MedicalStaffModule, // ✅ FIX LỖI: Cung cấp DentistService
  ],
  providers: [
    // --- Repositories & Ports ---
    { provide: IOrthoRepository, useClass: DrizzleOrthoRepository },
    { provide: IDentalStorage, useClass: FileSystemDentalStorage },
    { provide: IDentalWorker, useClass: PiscinaDentalWorker },

    // --- Infrastructure Providers (Bắt buộc phải có vì UseCase dùng nó) ---
    PiscinaProvider,
    DentalGateway,

    // --- Use Cases ---
    UploadCaseUseCase,          // ✅ Class gây lỗi giờ đã đủ đồ chơi
    ProcessMovementDataUseCase,

    // --- Queries ---
    GetCaseDetailsQuery,
    GetPatientHistoryQuery,
    GetCaseModelsQuery,

    // --- Chatbot ---
    DentalTreatmentChatbot,
    UploadAlignerScene,
  ],
  exports: [
    // Export để DentalModule (HTTP layer) dùng được
    IOrthoRepository,
    IDentalStorage,
    UploadCaseUseCase,
    ProcessMovementDataUseCase,
    GetCaseDetailsQuery,
    GetPatientHistoryQuery,
    GetCaseModelsQuery,
    DentalGateway, // Nếu Controller cần dùng
  ],
})
export class DentalTreatmentModule { }