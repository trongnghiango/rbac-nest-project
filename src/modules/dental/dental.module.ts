import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DentalController } from './infrastructure/controllers/dental.controller';
import { DentalService } from './application/services/dental.service';
import { PiscinaProvider } from './infrastructure/workers/piscina.provider';
import { FileSystemDentalStorage } from './infrastructure/adapters/fs-dental-storage.adapter';
import { PiscinaDentalWorker } from './infrastructure/adapters/piscina-worker.adapter';
import { DrizzleOrthoRepository } from './infrastructure/persistence/drizzle-ortho.repository';
import { IDentalStorage } from './domain/ports/dental-storage.port';
import { IDentalWorker } from './domain/ports/dental-worker.port';
import { IOrthoRepository } from './domain/repositories/ortho.repository';
import { DentalGateway } from './infrastructure/gateways/dental.gateway';
import dentalConfig from '@config/dental.config';

@Module({
  imports: [ConfigModule.forFeature(dentalConfig)],
  controllers: [DentalController],
  providers: [
    DentalService,
    PiscinaProvider,
    DentalGateway, // ✅ Added Gateway
    {
      provide: IDentalStorage,
      useClass: FileSystemDentalStorage,
    },
    {
      provide: IDentalWorker,
      useClass: PiscinaDentalWorker,
    },
    {
      provide: IOrthoRepository,
      useClass: DrizzleOrthoRepository,
    },
  ],
})
export class DentalModule {}
