#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🦷 REFACTORING DENTAL MODULE TO CLEAN ARCHITECTURE..."

BASE_DIR="src/modules/dental"

# 1. Tạo các Interface (Ports) ở Domain Layer
log "1️⃣ Defining Domain Ports..."
mkdir -p $BASE_DIR/domain/ports

cat > $BASE_DIR/domain/ports/dental-worker.port.ts << 'EOF'
export const IDentalWorker = Symbol('IDentalWorker');

export interface ConversionJob {
  objFilePath: string;
  outputDir: string;
  baseName: string;
  encryptionKey: string;
  config: {
    ratio: number;
    threshold: number;
    timeout: number;
  };
}

export interface WorkerResult {
  success: boolean;
  path: string;
}

export interface IDentalWorker {
  runTask(task: ConversionJob): Promise<WorkerResult>;
}
EOF

cat > $BASE_DIR/domain/ports/dental-storage.port.ts << 'EOF'
export const IDentalStorage = Symbol('IDentalStorage');

export interface DentalFile {
  path: string;
  filename: string;
}

export interface IDentalStorage {
  ensureDirectories(): void;
  saveTempFile(file: Express.Multer.File): Promise<string>;
  extractZip(zipPath: string, extractPath: string): Promise<void>;
  findObjFilesRecursively(dir: string): Promise<string[]>;
  findEncFilesRecursively(dir: string): Promise<string[]>;
  removeFile(path: string): Promise<void>;
  removeDirectory(path: string): Promise<void>;
  getUploadDir(): string;
  getOutputDir(): string;
}
EOF

# 2. Tạo Infrastructure Adapters
log "2️⃣ Creating Infrastructure Adapters..."
mkdir -p $BASE_DIR/infrastructure/adapters

# File System Adapter (Xử lý fs, path, adm-zip)
cat > $BASE_DIR/infrastructure/adapters/fs-dental-storage.adapter.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs-extra';
import * as path from 'path';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const AdmZip = require('adm-zip');
import { IDentalStorage } from '../../domain/ports/dental-storage.port';

@Injectable()
export class FileSystemDentalStorage implements IDentalStorage {
  private readonly uploadDir: string;
  private readonly outputDir: string;

  constructor(private readonly config: ConfigService) {
    const rawUploadDir = this.config.get('dental.uploadDir');
    const rawOutputDir = this.config.get('dental.outputDir');
    if (!rawUploadDir || !rawOutputDir) throw new Error('Dental Config Missing');

    this.uploadDir = path.resolve(rawUploadDir);
    this.outputDir = path.resolve(rawOutputDir);
  }

  ensureDirectories(): void {
    fs.ensureDirSync(this.uploadDir);
    fs.ensureDirSync(this.outputDir);
  }

  getUploadDir(): string { return this.uploadDir; }
  getOutputDir(): string { return this.outputDir; }

  async saveTempFile(file: Express.Multer.File): Promise<string> {
    // Multer đã lưu file rồi, hàm này chỉ để confirm hoặc move nếu cần
    return file.path;
  }

  async extractZip(zipPath: string, extractPath: string): Promise<void> {
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractPath, true);
  }

  async removeFile(path: string): Promise<void> {
    await fs.remove(path).catch(() => {});
  }

  async removeDirectory(path: string): Promise<void> {
    await fs.remove(path).catch(() => {});
  }

  async findObjFilesRecursively(dir: string): Promise<string[]> {
    return this.findFiles(dir, '.obj');
  }

  async findEncFilesRecursively(dir: string): Promise<string[]> {
    return this.findFiles(dir, '.enc');
  }

  private async findFiles(dir: string, ext: string): Promise<string[]> {
    let results: string[] = [];
    try {
        const list = await fs.readdir(dir);
        for (const file of list) {
            const fullPath = path.resolve(dir, file);
            const stat = await fs.stat(fullPath);
            if (stat && stat.isDirectory()) {
                results = results.concat(await this.findFiles(fullPath, ext));
            } else if (file.toLowerCase().endsWith(ext)) {
                results.push(fullPath);
            }
        }
    } catch (e) { /* ignore */ }
    return results;
  }
}
EOF

# Piscina Adapter (Xử lý Worker Pool)
cat > $BASE_DIR/infrastructure/adapters/piscina-worker.adapter.ts << 'EOF'
import { Injectable, Inject } from '@nestjs/common';
import Piscina from 'piscina';
import { IDentalWorker, ConversionJob, WorkerResult } from '../../domain/ports/dental-worker.port';
import { PISCINA_POOL } from '../workers/piscina.provider';

@Injectable()
export class PiscinaDentalWorker implements IDentalWorker {
  constructor(@Inject(PISCINA_POOL) private readonly pool: Piscina) {}

  async runTask(task: ConversionJob): Promise<WorkerResult> {
    return this.pool.run(task);
  }
}
EOF

# 3. Refactor Service (Clean Business Logic)
log "3️⃣ Refactoring Service to use Ports..."

cat > $BASE_DIR/application/services/dental.service.ts << 'EOF'
import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { IDentalStorage } from '../../domain/ports/dental-storage.port';
import { IDentalWorker, ConversionJob } from '../../domain/ports/dental-worker.port';

export interface ModelStep {
  index: number;
  maxillary: string | null;
  mandibular: string | null;
}

@Injectable()
export class DentalService {
  private readonly encryptionKey: string;
  private readonly appUrl: string;

  constructor(
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    @Inject(IDentalStorage) private readonly storage: IDentalStorage,
    @Inject(IDentalWorker) private readonly worker: IDentalWorker,
    private readonly config: ConfigService,
  ) {
    this.encryptionKey = this.config.get('dental.encryptionKey')!;
    this.appUrl = process.env.APP_URL || 'http://localhost:3000';
    this.storage.ensureDirectories();
  }

  async processZipUpload(file: Express.Multer.File, clientId: string) {
    if (!file) throw new BadRequestException('No file uploaded');

    const jobId = uuidv4();
    this.logger.info(`Processing ZIP for client ${clientId}`, { jobId, file: file.originalname });

    const extractPath = path.join(this.storage.getUploadDir(), `extract_${jobId}`);

    try {
        // 1. Extract (Qua Storage Port)
        await this.storage.extractZip(file.path, extractPath);

        // 2. Scan (Qua Storage Port)
        const objFiles = await this.storage.findObjFilesRecursively(extractPath);
        this.logger.info(`Found ${objFiles.length} OBJ files`, { jobId });

        // 3. Prepare Tasks
        const tasks = objFiles.map(objPath => {
            const relPath = path.relative(extractPath, objPath);
            const baseName = path.basename(objPath, '.obj');

            // Logic parse Index & Type
            const { type, index } = this.parseFileInfo(baseName, path.dirname(objPath));

            const standardizedName = `${type}_${index.toString().padStart(3, '0')}`;
            const targetDir = path.join(this.storage.getOutputDir(), clientId, type);

            const task: ConversionJob = {
                objFilePath: objPath,
                outputDir: targetDir,
                baseName: standardizedName,
                encryptionKey: this.encryptionKey,
                config: {
                    ratio: this.config.get('dental.simplificationRatio'),
                    threshold: this.config.get('dental.errorThreshold'),
                    timeout: this.config.get('dental.timeout'),
                }
            };
            return task;
        });

        // 4. Execute Workers (Qua Worker Port)
        const results = await Promise.allSettled(tasks.map(t => this.worker.runTask(t)));

        const successCount = results.filter(r => r.status === 'fulfilled').length;
        const failCount = results.filter(r => r.status === 'rejected').length;

        this.logger.info(`Job ${jobId} finished.`, { success: successCount, failed: failCount });

        return {
            message: 'Processing completed',
            jobId,
            stats: { total: tasks.length, success: successCount, failed: failCount }
        };

    } catch (error: any) {
        this.logger.error(`Error processing zip`, error, { jobId });
        throw new BadRequestException(`Failed: ${error.message}`);
    } finally {
        // Cleanup (Qua Storage Port)
        await Promise.all([
            this.storage.removeDirectory(extractPath),
            this.storage.removeFile(file.path)
        ]);
    }
  }

  async listModels(clientId: string): Promise<ModelStep[]> {
      const clientDir = path.join(this.storage.getOutputDir(), clientId);
      const allEncFiles = await this.storage.findEncFilesRecursively(clientDir);

      const stepsMap = new Map<number, ModelStep>();

      allEncFiles.forEach(fullPath => {
          const filename = path.basename(fullPath);
          const relativePath = path.relative(this.storage.getOutputDir(), fullPath);

          const urlPath = relativePath.split(path.sep).join('/');
          const encodedUrlPath = urlPath.split('/').map(encodeURIComponent).join('/');
          const url = `${this.appUrl}/models/${encodedUrlPath}`;

          const { type, index } = this.parseFileInfo(filename, path.dirname(fullPath));

          if (!stepsMap.has(index)) {
              stepsMap.set(index, { index, maxillary: null, mandibular: null });
          }

          const entry = stepsMap.get(index)!;
          if (type === 'Maxillary') entry.maxillary = url;
          else entry.mandibular = url;
      });

      return Array.from(stepsMap.values()).sort((a, b) => a.index - b.index);
  }

  // Helper tách logic parse tên file (Pure Domain Logic)
  private parseFileInfo(filename: string, dirPath: string): { type: 'Maxillary' | 'Mandibular', index: number } {
      let type: 'Maxillary' | 'Mandibular' = 'Maxillary';
      let index = 0;

      const lowerName = filename.toLowerCase();
      if (lowerName.includes('mandibular')) type = 'Mandibular';

      // Ưu tiên tìm trong tên thư mục cha (cho Subsetup)
      const parentDirName = path.basename(dirPath);
      const dirMatch = parentDirName.match(/(\d+)/);
      const fileMatch = filename.match(/(\d+)/);

      if (dirMatch) index = parseInt(dirMatch[1], 10);
      else if (fileMatch) index = parseInt(fileMatch[1], 10);

      return { type, index };
  }
}
EOF

# 4. Cập nhật Module (Wiring everything up)
log "4️⃣ Wiring Module..."

cat > $BASE_DIR/dental.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DentalController } from './infrastructure/controllers/dental.controller';
import { DentalService } from './application/services/dental.service';
import { PiscinaProvider } from './infrastructure/workers/piscina.provider';
import { FileSystemDentalStorage } from './infrastructure/adapters/fs-dental-storage.adapter';
import { PiscinaDentalWorker } from './infrastructure/adapters/piscina-worker.adapter';
import { IDentalStorage } from './domain/ports/dental-storage.port';
import { IDentalWorker } from './domain/ports/dental-worker.port';
import dentalConfig from '@config/dental.config';

@Module({
  imports: [ConfigModule.forFeature(dentalConfig)],
  controllers: [DentalController],
  providers: [
    DentalService,
    PiscinaProvider,
    {
      provide: IDentalStorage,
      useClass: FileSystemDentalStorage,
    },
    {
      provide: IDentalWorker,
      useClass: PiscinaDentalWorker,
    }
  ],
})
export class DentalModule {}
EOF

# 5. Fix Worker Type (Cập nhật import trong worker file gốc để khớp với port mới)
# Vì worker chạy process riêng, nên ta vẫn giữ file conversion.worker.ts ở infrastructure/workers
# Nhưng cần update lại một chút để dùng interface mới nếu cần (thực ra interface cũ vẫn compatible)
# Bước này optional nếu struct không đổi.

success "✅ REFACTOR COMPLETE! Dental Module is now Clean Architecture compliant."
echo "👉 Restart server: npm run start:dev"