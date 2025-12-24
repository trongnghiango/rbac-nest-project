import {
  Injectable,
  Inject,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Piscina from 'piscina';
import * as fs from 'fs-extra';
import * as path from 'path';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const AdmZip = require('adm-zip');
import { v4 as uuidv4 } from 'uuid';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';
import { PISCINA_POOL } from '../../infrastructure/workers/piscina.provider';
import { IOrthoRepository } from '../../domain/repositories/ortho.repository';
import { UploadCaseDto } from '../../infrastructure/dtos/upload-case.dto';
import { parseMovementExcel } from '../utils/movement.parser';

export interface ModelStep {
  index: number;
  maxillary: string | null;
  mandibular: string | null;
  // ✅ NEW: Thêm trường teethData trả về Frontend
  teethData?: Record<string, any>;
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
    @Inject(IOrthoRepository) private readonly orthoRepo: IOrthoRepository,
    private readonly config: ConfigService,
  ) {
    const rawUploadDir = this.config.get('dental.uploadDir');
    const rawOutputDir = this.config.get('dental.outputDir');
    this.appUrl = (process.env.APP_URL || 'http://localhost:3000').replace(
      /\/$/,
      '',
    );

    if (!rawUploadDir || !rawOutputDir)
      throw new Error('Dental configuration missing');

    this.uploadDir = path.resolve(rawUploadDir);
    this.outputDir = path.resolve(rawOutputDir);
    this.encryptionKey = this.config.get('dental.encryptionKey')!;

    fs.ensureDirSync(this.uploadDir);
    fs.ensureDirSync(this.outputDir);
  }

  // ... (processZipUpload giữ nguyên) ...
  async processZipUpload(file: Express.Multer.File, dto: UploadCaseDto) {
    if (!file) throw new BadRequestException('No file uploaded');

    const caseId = await this.orthoRepo.createFullCase({
      patientName: dto.patientName,
      patientCode: dto.patientCode,
      clinicName: dto.clinicName,
      doctorName: dto.doctorName,
      gender: dto.gender,
      productType: dto.productType,
      notes: dto.notes,
    });

    this.logger.info(
      `Processing upload for PatientCode: ${dto.patientCode} -> CaseID: ${caseId}`,
    );

    const jobId = uuidv4();
    const extractPath = path.join(this.uploadDir, `extract_${jobId}`);

    try {
      const zip = new AdmZip(file.path);
      zip.extractAllTo(extractPath, true);

      const objFiles = await this.findFilesRecursively(extractPath, '.obj');
      // if (objFiles.length === 0) throw new Error("No .obj files found"); // Cho phép upload 0 file nếu chỉ muốn tạo case

      const tasks = objFiles.map((objPath) => {
        const baseName = path.basename(objPath, '.obj');
        const parentDirPath = path.dirname(objPath);
        const parentDirName = path.basename(parentDirPath);

        let type: 'Maxillary' | 'Mandibular' = 'Maxillary';
        if (baseName.toLowerCase().includes('mandibular')) type = 'Mandibular';

        let index = 0;
        const explicitFolderMatch = parentDirName.match(
          /(?:Subsetup|Stage|Step)[^0-9]*(\d+)/i,
        );
        const fileNumberMatch = baseName.match(/[ _-](\d+)$/);

        if (explicitFolderMatch) index = parseInt(explicitFolderMatch[1], 10);
        else if (fileNumberMatch) index = parseInt(fileNumberMatch[1], 10);
        else if (/^\d+$/.test(parentDirName))
          index = parseInt(parentDirName, 10);

        const standardizedName = `${type}_${index.toString().padStart(3, '0')}`;
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
          meta: { index, type },
        };
      });

      await Promise.allSettled(tasks.map((t) => this.pool.run(t)));
      return {
        message: 'Processing completed',
        caseId: caseId,
        patientCode: dto.patientCode,
      };
    } catch (error: any) {
      this.logger.error(`Error processing case ${caseId}`, error);
      throw new BadRequestException(`Processing failed: ${error.message}`);
    } finally {
      await Promise.all([
        fs.remove(extractPath).catch(() => {}),
        fs.remove(file.path).catch(() => {}),
      ]);
    }
  }

  // ✅ NEW: Xử lý Upload Excel Movement
  async processMovementExcel(file: Express.Multer.File, caseId: string) {
    this.logger.info(`Processing Movement Excel for Case: ${caseId}`);
    try {
      // Đọc dữ liệu từ ổ cứng vì buffer bị undefined khi dùng diskStorage
      const fileBuffer = await fs.readFile(file.path);
      const stepsDataMap = parseMovementExcel(fileBuffer);
      let count = 0;

      for (const [stepIndex, teethData] of stepsDataMap.entries()) {
        await this.orthoRepo.updateStepMovementData(
          caseId,
          stepIndex,
          teethData,
        );
        count++;
      }

      // Xóa file tạm sau khi thành công
      await fs.remove(file.path).catch(() => {});

      this.logger.info(`Updated movement data for ${count} steps.`);
      return {
        message: 'Movement data updated successfully',
        stepsCount: count,
      };
    } catch (error: any) {
      // Đảm bảo xóa file tạm kể cả khi lỗi
      if (file?.path) await fs.remove(file.path).catch(() => {});
      this.logger.error(`Excel Parse Error`, error);
      throw new BadRequestException(`Failed to parse file: ${error.message}`);
    }
  }

  async getCaseDetails(clientIdOrCode: string, specificCaseId?: string) {
    if (specificCaseId) {
      const isValid = await this.orthoRepo.checkCaseBelongsToPatient(
        specificCaseId,
        clientIdOrCode,
      );
      if (!isValid)
        throw new NotFoundException(
          `Case not found for patient ${clientIdOrCode}`,
        );
      return this.orthoRepo.getCaseDetails(specificCaseId, true);
    } else {
      return this.orthoRepo.getCaseDetails(clientIdOrCode, false);
    }
  }

  // ✅ UPDATED: List Models bao gồm cả Movement Data từ DB
  async listModels(
    clientIdOrCode: string,
    specificCaseId?: string,
  ): Promise<ModelStep[]> {
    let targetFolder = '';
    let dbCaseId = ''; // ID số trong DB

    if (specificCaseId) {
      const isValid = await this.orthoRepo.checkCaseBelongsToPatient(
        specificCaseId,
        clientIdOrCode,
      );
      if (!isValid)
        throw new NotFoundException(
          `Case not found for patient ${clientIdOrCode}`,
        );
      targetFolder = specificCaseId;
      dbCaseId = specificCaseId;
    } else {
      const latestCaseId =
        await this.orthoRepo.findLatestCaseIdByCode(clientIdOrCode);
      if (latestCaseId) {
        targetFolder = latestCaseId;
        dbCaseId = latestCaseId;
      } else if (fs.existsSync(path.join(this.outputDir, clientIdOrCode))) {
        targetFolder = clientIdOrCode;
        // Legacy folder không có trong DB thì không có movement data
      }
    }

    if (!targetFolder) return [];

    // 1. Quét File System để lấy danh sách file 3D
    const clientDir = path.join(this.outputDir, targetFolder);
    const allEncFiles = fs.existsSync(clientDir)
      ? await this.findFilesRecursively(clientDir, '.enc')
      : [];

    // 2. Query DB để lấy Movement Data (nếu có CaseID hợp lệ)
    let dbSteps: any[] = [];
    if (dbCaseId && !isNaN(Number(dbCaseId))) {
      dbSteps = await this.orthoRepo.getStepsByCaseId(Number(dbCaseId));
    }

    // 3. Merge Data (File System + DB)
    const stepsMap = new Map<number, ModelStep>();

    // Populate từ DB trước (để lấy teethData)
    dbSteps.forEach((dbStep) => {
      if (!stepsMap.has(dbStep.stepIndex)) {
        stepsMap.set(dbStep.stepIndex, {
          index: dbStep.stepIndex,
          maxillary: null,
          mandibular: null,
          teethData: dbStep.teethData, // ✅ Attach Data
        });
      }
    });

    // Populate từ File System (để lấy URL file)
    allEncFiles.forEach((fullPath) => {
      const filename = path.basename(fullPath).toLowerCase();
      const relativePath = path.relative(this.outputDir, fullPath);
      const urlPath = relativePath
        .split(path.sep)
        .map(encodeURIComponent)
        .join('/');
      const url = `${this.appUrl}/models/${urlPath}`;

      let index = 0;
      let type: 'maxillary' | 'mandibular' | null = null;
      if (filename.includes('maxillary')) type = 'maxillary';
      else if (filename.includes('mandibular')) type = 'mandibular';

      if (!type) return;

      const fileMatch = filename.match(/(\d+)/);
      if (fileMatch) index = parseInt(fileMatch[1], 10);

      if (!stepsMap.has(index)) {
        stepsMap.set(index, { index, maxillary: null, mandibular: null });
      }
      const entry = stepsMap.get(index)!;
      if (type === 'maxillary') entry.maxillary = url;
      else entry.mandibular = url;
    });

    return Array.from(stepsMap.values()).sort((a, b) => a.index - b.index);
  }

  async getHistory(patientCode: string) {
    return this.orthoRepo.findCasesByPatientCode(patientCode);
  }

  private async findFilesRecursively(
    dir: string,
    ext: string,
  ): Promise<string[]> {
    let results: string[] = [];
    try {
      const list = await fs.readdir(dir);
      for (const file of list) {
        const fullPath = path.resolve(dir, file);
        const stat = await fs.stat(fullPath);
        if (stat && stat.isDirectory()) {
          results = results.concat(
            await this.findFilesRecursively(fullPath, ext),
          );
        } else if (file.toLowerCase().endsWith(ext)) {
          results.push(fullPath);
        }
      }
    } catch (e) {}
    return results;
  }
}
