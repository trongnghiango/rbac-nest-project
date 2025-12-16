#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🦷 UPGRADING DENTAL SERVICE TO DEEP SCAN MODE..."

cat > src/modules/dental/application/services/dental.service.ts << 'EOF'
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

export interface ModelStep {
  index: number;
  maxillary: string | null;
  mandibular: string | null;
}

@Injectable()
export class DentalService {
  private readonly uploadDir: string;
  private readonly outputDir: string;
  private readonly encryptionKey: string;
  private readonly appUrl: string;

  constructor(
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    @Inject(PISCINA_POOL) private readonly pool: Piscina,
    private readonly config: ConfigService,
  ) {
    const rawUploadDir = this.config.get('dental.uploadDir');
    const rawOutputDir = this.config.get('dental.outputDir');

    this.appUrl = process.env.APP_URL || 'http://localhost:3000';

    if (!rawUploadDir || !rawOutputDir) {
        throw new Error('Dental configuration missing');
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

        const objFiles = await this.findFilesRecursively(extractPath, '.obj');
        this.logger.info(`Found ${objFiles.length} OBJ files`, { jobId });

        const tasks = objFiles.map(objPath => {
            const relPath = path.relative(extractPath, objPath);
            const baseName = path.basename(objPath, '.obj');

            // Giữ nguyên cấu trúc thư mục con để tránh ghi đè nếu file trùng tên
            const subDir = path.dirname(relPath);
            const targetDir = path.join(this.outputDir, clientId, subDir);

            // Tên file output giữ nguyên gốc + đuôi mở rộng
            const finalName = `${baseName}.optimized.glb.enc`;

            const task: ConversionTask = {
                objFilePath: objPath,
                outputDir: targetDir,
                baseName: baseName, // Worker sẽ tự thêm đuôi
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
        await Promise.all([
            fs.remove(extractPath).catch(() => {}),
            fs.remove(file.path).catch(() => {})
        ]);
    }
  }

  // ✅ FIX: QUÉT SÂU (DEEP SCAN) VÀ PHÂN TÍCH INDEX THÔNG MINH
  async listModels(clientId: string): Promise<ModelStep[]> {
      const clientDir = path.join(this.outputDir, clientId);

      if (!fs.existsSync(clientDir)) {
          this.logger.warn(`Client directory not found`, { path: clientDir });
          return [];
      }

      // 1. Tìm tất cả file .enc bất kể nằm sâu cỡ nào
      const allEncFiles = await this.findFilesRecursively(clientDir, '.enc');

      this.logger.debug(`Scanned files for client ${clientId}`, {
          found: allEncFiles.length,
          rootPath: clientDir
      });

      const stepsMap = new Map<number, ModelStep>();

      allEncFiles.forEach(fullPath => {
          const filename = path.basename(fullPath).toLowerCase();
          const relativePath = path.relative(this.outputDir, fullPath);

          // Tạo URL chuẩn: http://localhost:3000/models/{relativePath}
          // Thay thế dấu \ (Windows) bằng /
          const urlPath = relativePath.split(path.sep).join('/');
          // Encode từng phần của URL để xử lý dấu cách, ký tự lạ trong tên thư mục
          const encodedUrlPath = urlPath.split('/').map(encodeURIComponent).join('/');
          const url = `${this.appUrl}/models/${encodedUrlPath}`;

          // --- LOGIC PHÂN TÍCH INDEX ---
          let index = 0;
          let type: 'maxillary' | 'mandibular' | null = null;

          // Xác định loại (Hàm trên / Hàm dưới)
          if (filename.includes('maxillary')) type = 'maxillary';
          else if (filename.includes('mandibular')) type = 'mandibular';

          if (!type) return; // Bỏ qua nếu không xác định được loại

          // Xác định Index (Số bước)
          // 1. Tìm trong tên file trước (VD: Maxillary_01.enc)
          const fileMatch = filename.match(/(\d+)/);

          // 2. Tìm trong đường dẫn thư mục (Quan trọng với cấu trúc của bạn: "Subsetup (1)")
          // Lấy tên thư mục cha
          const parentDirName = path.basename(path.dirname(fullPath));
          const dirMatch = parentDirName.match(/(\d+)/);

          if (dirMatch) {
              index = parseInt(dirMatch[1], 10);
          } else if (fileMatch) {
              index = parseInt(fileMatch[1], 10);
          }
          // Nếu không tìm thấy số nào, mặc định là 0

          // Lưu vào Map
          if (!stepsMap.has(index)) {
              stepsMap.set(index, { index, maxillary: null, mandibular: null });
          }

          const entry = stepsMap.get(index)!;
          if (type === 'maxillary') entry.maxillary = url;
          else entry.mandibular = url;
      });

      // Chuyển Map thành Array và sắp xếp
      const result = Array.from(stepsMap.values()).sort((a, b) => a.index - b.index);

      this.logger.info(`Generated model list`, { clientId, stepsCount: result.length });
      return result;
  }

  // Hàm đệ quy tìm file
  private async findFilesRecursively(dir: string, ext: string): Promise<string[]> {
    let results: string[] = [];
    try {
        const list = await fs.readdir(dir);
        for (const file of list) {
            const fullPath = path.resolve(dir, file);
            const stat = await fs.stat(fullPath);
            if (stat && stat.isDirectory()) {
                results = results.concat(await this.findFilesRecursively(fullPath, ext));
            } else if (file.toLowerCase().endsWith(ext)) {
                results.push(fullPath);
            }
        }
    } catch (e) {
        // Ignore read errors
    }
    return results;
  }
}
EOF

success "✅ DEEP SCAN LOGIC APPLIED! API will now find files in nested folders."
echo "👉 Restart server: npm run start:dev"
echo "👉 Call API again. It should work with existing files."