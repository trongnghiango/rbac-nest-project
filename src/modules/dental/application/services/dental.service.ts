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
import { IOrthoRepository } from '../../domain/repositories/ortho.repository';
import { UploadCaseDto } from '../../infrastructure/dtos/upload-case.dto';

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
    @Inject(IOrthoRepository) private readonly orthoRepo: IOrthoRepository, // Inject Repository
    private readonly config: ConfigService,
  ) {
    const rawUploadDir = this.config.get('dental.uploadDir');
    const rawOutputDir = this.config.get('dental.outputDir');
    this.appUrl = (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, "");

    if (!rawUploadDir || !rawOutputDir) throw new Error('Dental configuration missing');

    this.uploadDir = path.resolve(rawUploadDir);
    this.outputDir = path.resolve(rawOutputDir);
    this.encryptionKey = this.config.get('dental.encryptionKey')!;

    fs.ensureDirSync(this.uploadDir);
    fs.ensureDirSync(this.outputDir);
  }

  // ✅ LOGIC MỚI: Nhận DTO, Tạo DB record trước, sau đó xử lý file
  async processZipUpload(file: Express.Multer.File, dto: UploadCaseDto) {
    if (!file) throw new BadRequestException('No file uploaded');

    // 1. Lưu thông tin vào DB để lấy Case ID
    const caseId = await this.orthoRepo.createFullCase({
        patientName: dto.patientName,
        patientCode: dto.patientCode,
        clinicName: dto.clinicName,
        doctorName: dto.doctorName,
        gender: dto.gender,
        dob: dto.dob ? new Date(dto.dob) : undefined,
        productType: dto.productType,
        notes: dto.notes
    });

    this.logger.info(`Created Case ID: ${caseId} for Patient: ${dto.patientName}`);

    const jobId = uuidv4();
    const extractPath = path.join(this.uploadDir, `extract_${jobId}`);

    try {
        const zip = new AdmZip(file.path);
        zip.extractAllTo(extractPath, true);

        const objFiles = await this.findFilesRecursively(extractPath, '.obj');
        this.logger.info(`Found ${objFiles.length} OBJ files`, { jobId });

        // 2. Chuẩn bị task convert
        // Output Dir bây giờ dựa trên Case ID (Database ID) thay vì clientId tùy ý
        const tasks = objFiles.map(objPath => {
            const relPath = path.relative(extractPath, objPath);
            const baseName = path.basename(objPath, '.obj');

            // Logic parse type và index (giữ nguyên logic cũ vì nó tốt)
            let type: 'Maxillary' | 'Mandibular' = 'Maxillary';
            let index = 0;
            if (baseName.toLowerCase().includes('mandibular')) type = 'Mandibular';

            const parentDir = path.dirname(objPath);
            const dirMatch = parentDir.match(/(\d+)/);
            const fileMatch = baseName.match(/(\d+)/);

            if (dirMatch) index = parseInt(dirMatch[1], 10);
            else if (fileMatch) index = parseInt(fileMatch[1], 10);

            const standardizedName = `${type}_${index.toString().padStart(3, '0')}`;

            // LƯU VÀO FOLDER THEO CASE ID
            const targetDir = path.join(this.outputDir, caseId, type);

            return {
                objFilePath: objPath,
                outputDir: targetDir,
                baseName: standardizedName,
                encryptionKey: this.encryptionKey,
                config: {
                    ratio: this.config.get('dental.simplificationRatio'),
                    threshold: this.config.get('dental.errorThreshold'),
                    timeout: this.config.get('dental.timeout'),
                },
                // Metadata để dùng sau này lưu vào DB steps (nếu cần mở rộng worker trả về)
                meta: { index, type }
            };
        });

        // 3. Chạy Worker
        await Promise.allSettled(tasks.map(t => this.pool.run(t)));

        // 4. (Optional) Lưu thông tin Steps vào DB
        // Hiện tại Worker chỉ trả về success/fail.
        // Để Pro hơn, ta có thể xây dựng map steps và gọi orthoRepo.saveSteps(caseId, ...)
        // Nhưng tạm thời để Frontend list file hoạt động, ta chỉ cần file nằm đúng chỗ.

        // Update Status thành DONE (Cần thêm hàm update status trong repo, tạm bỏ qua)

        return {
            message: 'Case created and processing started',
            caseId: caseId,
            jobId
        };

    } catch (error: any) {
        this.logger.error(`Error processing case ${caseId}`, error);
        throw new BadRequestException(`Processing failed: ${error.message}`);
    } finally {
        await Promise.all([
            fs.remove(extractPath).catch(() => {}),
            fs.remove(file.path).catch(() => {})
        ]);
    }
  }

  async listModels(caseId: string): Promise<ModelStep[]> {
      // Logic list models bây giờ dựa vào Case ID (số ID trong DB)
      const clientDir = path.join(this.outputDir, caseId);

      if (!fs.existsSync(clientDir)) return [];

      const allEncFiles = await this.findFilesRecursively(clientDir, '.enc');
      const stepsMap = new Map<number, ModelStep>();

      allEncFiles.forEach(fullPath => {
          const filename = path.basename(fullPath).toLowerCase();
          const relativePath = path.relative(this.outputDir, fullPath);
          const urlPath = relativePath.split(path.sep).map(encodeURIComponent).join('/');
          const url = `${this.appUrl}/models/${urlPath}`;

          let index = 0;
          let type: 'maxillary' | 'mandibular' | null = null;
          if (filename.includes('maxillary')) type = 'maxillary';
          else if (filename.includes('mandibular')) type = 'mandibular';

          if (!type) return;

          const fileMatch = filename.match(/(\d+)/);
          const parentDirName = path.basename(path.dirname(fullPath));
          const dirMatch = parentDirName.match(/(\d+)/);

          if (dirMatch) index = parseInt(dirMatch[1], 10);
          else if (fileMatch) index = parseInt(fileMatch[1], 10);

          if (!stepsMap.has(index)) stepsMap.set(index, { index, maxillary: null, mandibular: null });
          const entry = stepsMap.get(index)!;
          if (type === 'maxillary') entry.maxillary = url;
          else entry.mandibular = url;
      });

      return Array.from(stepsMap.values()).sort((a, b) => a.index - b.index);
  }

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
    } catch (e) { }
    return results;
  }
}
