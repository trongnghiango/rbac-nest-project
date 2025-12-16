import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DentalController } from './infrastructure/controllers/dental.controller';
import { DentalService } from './application/services/dental.service';
import { PiscinaProvider } from './infrastructure/workers/piscina.provider';
import dentalConfig from '@config/dental.config';

@Module({
  imports: [ConfigModule.forFeature(dentalConfig)],
  controllers: [DentalController],
  providers: [
    DentalService,
    PiscinaProvider,
  ],
})
export class DentalModule {}
