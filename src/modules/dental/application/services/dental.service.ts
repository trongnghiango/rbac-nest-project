import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';
import { IDentalStorage } from '../../domain/ports/dental-storage.port';
import {
  IDentalWorker,
  ConversionJob,
} from '../../domain/ports/dental-worker.port';

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
    this.logger.info(`Processing ZIP for client ${clientId}`, {
      jobId,
      file: file.originalname,
    });

    const extractPath = path.join(
      this.storage.getUploadDir(),
      `extract_${jobId}`,
    );

    try {
      // 1. Extract (Qua Storage Port)
      await this.storage.extractZip(file.path, extractPath);

      // 2. Scan (Qua Storage Port)
      const objFiles = await this.storage.findObjFilesRecursively(extractPath);
      this.logger.info(`Found ${objFiles.length} OBJ files`, { jobId });

      // 3. Prepare Tasks
      const tasks = objFiles.map((objPath) => {
        const relPath = path.relative(extractPath, objPath);
        const baseName = path.basename(objPath, '.obj');

        // Logic parse Index & Type
        const { type, index } = this.parseFileInfo(
          baseName,
          path.dirname(objPath),
        );

        const standardizedName = `${type}_${index.toString().padStart(3, '0')}`;
        const targetDir = path.join(
          this.storage.getOutputDir(),
          clientId,
          type,
        );

        const task: ConversionJob = {
          objFilePath: objPath,
          outputDir: targetDir,
          baseName: standardizedName,
          encryptionKey: this.encryptionKey,
          config: {
            ratio: this.config.get('dental.simplificationRatio'),
            threshold: this.config.get('dental.errorThreshold'),
            timeout: this.config.get('dental.timeout'),
          },
        };
        return task;
      });

      // 4. Execute Workers (Qua Worker Port)
      const results = await Promise.allSettled(
        tasks.map((t) => this.worker.runTask(t)),
      );

      const successCount = results.filter(
        (r) => r.status === 'fulfilled',
      ).length;
      const failCount = results.filter((r) => r.status === 'rejected').length;

      this.logger.info(`Job ${jobId} finished.`, {
        success: successCount,
        failed: failCount,
      });

      return {
        message: 'Processing completed',
        jobId,
        stats: {
          total: tasks.length,
          success: successCount,
          failed: failCount,
        },
      };
    } catch (error: any) {
      this.logger.error(`Error processing zip`, error, { jobId });
      throw new BadRequestException(`Failed: ${error.message}`);
    } finally {
      // Cleanup (Qua Storage Port)
      await Promise.all([
        this.storage.removeDirectory(extractPath),
        this.storage.removeFile(file.path),
      ]);
    }
  }

  async listModels(clientId: string): Promise<ModelStep[]> {
    const clientDir = path.join(this.storage.getOutputDir(), clientId);
    const allEncFiles = await this.storage.findEncFilesRecursively(clientDir);

    const stepsMap = new Map<number, ModelStep>();

    allEncFiles.forEach((fullPath) => {
      const filename = path.basename(fullPath);
      const relativePath = path.relative(this.storage.getOutputDir(), fullPath);

      const urlPath = relativePath.split(path.sep).join('/');
      const encodedUrlPath = urlPath
        .split('/')
        .map(encodeURIComponent)
        .join('/');
      const url = `${this.appUrl}/models/${encodedUrlPath}`;

      const { type, index } = this.parseFileInfo(
        filename,
        path.dirname(fullPath),
      );

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
  private parseFileInfo(
    filename: string,
    dirPath: string,
  ): { type: 'Maxillary' | 'Mandibular'; index: number } {
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
