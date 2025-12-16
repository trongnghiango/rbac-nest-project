import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Piscina from 'piscina';

import * as fs from 'fs-extra';
import * as path from 'path';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const AdmZip = require('adm-zip');

import { v4 as uuidv4 } from 'uuid';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { PISCINA_POOL } from '../../infrastructure/workers/piscina.provider';
import { ConversionTask } from '../../infrastructure/workers/conversion.worker';

@Injectable()
export class DentalService {
  private readonly uploadDir: string;
  private readonly outputDir: string;
  private readonly encryptionKey: string;

  constructor(
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    @Inject(PISCINA_POOL) private readonly pool: Piscina,
    private readonly config: ConfigService,
  ) {
    const rawUploadDir = this.config.get('dental.uploadDir');
    const rawOutputDir = this.config.get('dental.outputDir');

    if (!rawUploadDir || !rawOutputDir) {
        throw new Error('Dental configuration missing: uploadDir or outputDir');
    }

    this.uploadDir = path.resolve(rawUploadDir);
    this.outputDir = path.resolve(rawOutputDir);
    this.encryptionKey = this.config.get('dental.encryptionKey')!;

    fs.ensureDirSync(this.uploadDir);
    fs.ensureDirSync(this.outputDir);
  }

  async processZipUpload(file: Express.Multer.File, clientId: string) {
    if (!file) throw new BadRequestException('No file uploaded');

    const jobId = uuidv4();
    this.logger.info(`Processing ZIP for client ${clientId}`, { jobId, file: file.originalname });

    const extractPath = path.join(this.uploadDir, `extract_${jobId}`);

    try {
        const zip = new AdmZip(file.path);
        zip.extractAllTo(extractPath, true);

        const objFiles = await this.findFiles(extractPath, '.obj');

        this.logger.info(`Found ${objFiles.length} OBJ files`, { jobId });

        const tasks = objFiles.map(objPath => {
            const relPath = path.relative(extractPath, objPath);
            const baseName = path.basename(objPath, '.obj');
            const subDir = path.dirname(relPath);
            const targetDir = path.join(this.outputDir, clientId, subDir);

            const task: ConversionTask = {
                objFilePath: objPath,
                outputDir: targetDir,
                baseName: baseName,
                encryptionKey: this.encryptionKey,
                config: {
                    ratio: this.config.get('dental.simplificationRatio'),
                    threshold: this.config.get('dental.errorThreshold'),
                    timeout: this.config.get('dental.timeout'),
                }
            };
            return task;
        });

        const results = await Promise.allSettled(tasks.map(t => this.pool.run(t)));

        const successCount = results.filter(r => r.status === 'fulfilled').length;
        const failCount = results.filter(r => r.status === 'rejected').length;

        this.logger.info(`Job ${jobId} finished. Success: ${successCount}, Failed: ${failCount}`);

        return {
            message: 'Processing completed',
            jobId,
            stats: { total: tasks.length, success: successCount, failed: failCount }
        };

    } catch (error: any) {
        // ✅ FIX: Truyền 'error' object vào tham số thứ 2, 'context' vào tham số thứ 3
        this.logger.error(`Error processing zip`, error, { jobId });
        throw new BadRequestException(`Failed to process zip file: ${error.message}`);
    } finally {
        await Promise.all([
            fs.remove(extractPath).catch(() => {}),
            fs.remove(file.path).catch(() => {})
        ]);
    }
  }

  async listModels(clientId: string) {
      const clientDir = path.join(this.outputDir, clientId);
      if (!fs.existsSync(clientDir)) return [];
      return this.findFiles(clientDir, '.enc');
  }

  private async findFiles(dir: string, ext: string): Promise<string[]> {
    let results: string[] = [];
    try {
        const list = await fs.readdir(dir);
        for (const file of list) {
            const filePath = path.resolve(dir, file);
            const stat = await fs.stat(filePath);
            if (stat && stat.isDirectory()) {
                results = results.concat(await this.findFiles(filePath, ext));
            } else if (filePath.toLowerCase().endsWith(ext)) {
                results.push(filePath);
            }
        }
    } catch (e) {
        // Ignore errors
    }
    return results;
  }
}
