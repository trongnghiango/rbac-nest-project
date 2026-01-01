import { Module, OnModuleInit, Inject } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MulterModule } from '@nestjs/platform-express'; // ✅ Import MulterModule
import { diskStorage } from 'multer';

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
  imports: [
    ConfigModule.forFeature(dentalConfig),
    // ✅ Cấu hình Multer Asynchronously (Dynamic Config)
    MulterModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (config: ConfigService) => ({
        storage: diskStorage({
          destination: (req, file, cb) => {
            // Lấy đường dẫn từ Config (đồng bộ với IDentalStorage)
            const uploadDir =
              config.get<string>('dental.uploadDir') || 'uploads/dental/temp';
            cb(null, uploadDir);
          },
          filename: (req, file, cb) => {
            // Giữ logic đặt tên file có timestamp để tránh trùng
            cb(null, `${Date.now()}-${file.originalname}`);
          },
        }),
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [DentalController],
  providers: [
    DentalService,
    PiscinaProvider,
    DentalGateway,
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
export class DentalModule implements OnModuleInit {
  constructor(
    @Inject(IDentalStorage) private readonly dentalStorage: IDentalStorage,
  ) {}

  // ✅ Lifecycle Hook: Chạy 1 lần duy nhất khi Module khởi tạo
  // Đảm bảo thư mục tồn tại TRƯỚC khi có bất kỳ request nào.
  onModuleInit() {
    this.dentalStorage.ensureDirectories();
  }
}
