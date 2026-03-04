import {
  Injectable,
  Inject,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { v4 as uuidv4 } from 'uuid';
import Piscina from 'piscina';

// Core Ports
import {
  ITransactionManager,
  Transaction,
} from '@core/shared/application/ports/transaction-manager.port';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';

// Repositories & Ports (Local Module)
import { IOrthoRepository } from '../../domain/repositories/ortho.repository'; // Interface cũ chứa Case logic
import { IDentalStorage } from '../../domain/ports/dental-storage.port';
import {
  ConversionTaskWithMeta,
  JawType,
} from '../../domain/types/dental.types';
import { UploadCaseDto } from '../dtos/upload-case.dto';

// Services from Other Modules (Inject trực tiếp Service Class)
import { ClinicService } from '@modules/organization/domain/services/clinic.service';
import { PatientService } from '@modules/patient/domain/services/patient.service';
import { DentistService } from '@modules/medical-staff/domain/services/dentist.service';

// Infra Workers
import { PISCINA_POOL } from '../../infrastructure/workers/piscina.provider';
import { DentalGateway } from '../../infrastructure/gateways/dental.gateway';
import { parseMovementData } from '../utils/movement.parser';

@Injectable()
export class UploadCaseUseCase {
  private readonly appUrl: string;

  constructor(
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    @Inject(ITransactionManager)
    private readonly txManager: ITransactionManager,

    // Repositories Local
    @Inject(IOrthoRepository) private readonly caseRepo: IOrthoRepository,
    @Inject(IDentalStorage) private readonly storage: IDentalStorage,

    // External Domain Services
    private readonly clinicService: ClinicService,
    private readonly patientService: PatientService,
    private readonly dentistService: DentistService,

    // Workers & Helpers
    @Inject(PISCINA_POOL) private readonly pool: Piscina,
    private readonly config: ConfigService,
    private readonly dentalGateway: DentalGateway,
  ) {
    this.appUrl = (process.env.APP_URL || 'http://localhost:8080').replace(
      /\/$/,
      '',
    );
  }

  async execute(file: Express.Multer.File, dto: UploadCaseDto) {
    if (!file) throw new BadRequestException('No file uploaded');

    const isOverwrite = String(dto.overwrite) === 'true';
    let caseId: string | null = null;

    // 1. Handle Overwrite Logic
    if (isOverwrite) {
      caseId = await this.caseRepo.findLatestCaseIdByCode(dto.patientCode);
      if (caseId) {
        this.logger.warn(`Cleaning Case ${caseId} for overwrite`);
        const caseDir = this.storage.joinPath(this.storage.outputDir, caseId);
        await this.storage.remove(caseDir);
        await this.caseRepo.deleteStepsByCaseId(Number(caseId));
      }
    }

    // 2. Main Transaction: Create/Get Entities
    if (!caseId) {
      caseId = await this.txManager.runInTransaction(
        async (tx: Transaction) => {
          // A. Organization
          const clinic = await this.clinicService.ensureClinicExists(
            dto.clinicName,
            undefined,
            tx,
          );

          // B. Medical Staff
          let dentistId: number | undefined;
          if (dto.doctorName) {
            const dentist = await this.dentistService.ensureDentistExists(
              dto.doctorName,
              clinic.id,
              tx,
            );
            dentistId = dentist.id;
          }

          // C. Patient
          const dobString = dto.dob
            ? new Date(dto.dob).toISOString().split('T')[0]
            : undefined;
          const patient = await this.patientService.ensurePatientExists(
            {
              code: dto.patientCode,
              name: dto.patientName,
              gender: dto.gender,
              dob: dobString,
            },
            clinic.id,
            tx,
          );

          // D. Create Case (Local Module Logic)
          const newCase = await this.caseRepo.createCase(
            {
              patientId: patient.id,
              dentistId: dentistId ?? null,
              productType: dto.productType,
              notes: dto.notes,
            },
            tx,
          );
          return String(newCase.id);
        },
      );
    }

    // 3. File Processing (Zip Extraction & Queueing)
    const extractPath = this.storage.joinPath(
      this.storage.uploadDir,
      `extract_${uuidv4()}`,
    );

    try {
      await this.storage.extractZip(file.path, extractPath);
    } catch (e: any) {
      throw new BadRequestException('Invalid Zip File: ' + e.message);
    }

    // ============================================================
    // 👉 NEW LOGIC: PROCESS HTML MOVEMENT DATA (SYNC)
    // ============================================================
    try {
      // Tìm file .html hoặc .htm
      const htmlFiles = await this.storage.findFilesRecursively(extractPath, '.html');
      // Nếu không thấy .html, thử tìm .htm
      if (htmlFiles.length === 0) {
        const htmFiles = await this.storage.findFilesRecursively(extractPath, '.htm');
        htmlFiles.push(...htmFiles);
      }

      if (htmlFiles.length > 0) {
        // Lấy file đầu tiên tìm được (thường là report)
        const reportPath = htmlFiles[0];
        this.logger.info(`📄 Found movement report: ${this.storage.getBasename(reportPath)}`);
        
        const reportBuffer = await this.storage.readFile(reportPath);
        
        // Parse dữ liệu
        const movementMap = parseMovementData(reportBuffer, this.storage.getBasename(reportPath));
        
        // Lưu vào DB (Bulk Upsert)
        await this.caseRepo.saveSteps(Number(caseId), movementMap);
        
        this.logger.info(`✅ Updated movement data for Case ${caseId}: ${movementMap.size} steps.`);
      } else {
        this.logger.warn(`⚠️ No HTML report found for Case ${caseId}. Skipping movement data update.`);
      }
    } catch (error) {
      // ⚠️ Quan trọng: Lỗi parse HTML không nên chặn luồng xử lý 3D Model chính
      // Chỉ log error và tiếp tục
      this.logger.error(`❌ Failed to process HTML report for Case ${caseId}`, error);
    }

    // ============================================================
    // 👉 END NEW LOGIC
    // ============================================================

    // 4. Processing 3D Models (Queueing Tasks)
    const objFiles = await this.storage.findFilesRecursively(
      extractPath,
      '.obj',
    );

    // Prepare Tasks
    const binariesConfig = {
      obj2gltf: this.config.get<string>('dental.binaries.obj2gltf')!,
      gltfPipeline: this.config.get<string>('dental.binaries.gltfPipeline')!,
      gltfTransform: this.config.get<string>('dental.binaries.gltfTransform')!,
    };

    const tasks: ConversionTaskWithMeta[] = objFiles.map((objPath) => {
      const baseName = this.storage.getBasename(objPath, '.obj');
      const parentDir = this.storage.getBasename(
        this.storage.getDirname(objPath),
      );

      const type: JawType = baseName.toLowerCase().includes('mandibular')
        ? 'Mandibular'
        : 'Maxillary';

      let index = 0;
      const folderMatch = parentDir.match(/(\d+)/);
      const fileMatch = baseName.match(/(\d+)/);
      if (folderMatch) index = parseInt(folderMatch[1], 10);
      else if (fileMatch) index = parseInt(fileMatch[1], 10);

      return {
        objFilePath: objPath,
        outputDir: this.storage.joinPath(this.storage.outputDir, caseId!, type),
        baseName: `${type}_${index.toString().padStart(3, '0')}`,
        encryptionKey: this.config.get<string>('dental.encryptionKey')!,
        config: { ratio: 0.3, threshold: 0.0005, timeout: 300000 },
        binaries: binariesConfig,
        meta: { index, type },
      };
    });

    this.logger.info(
      `Queueing ${tasks.length} conversion tasks for Case ${caseId}`,
    );

    // Fire and Forget (Background Process)
    this.runBackgroundConversion(tasks, caseId!, extractPath, file.path);

    return {
      success: true,
      message: 'Processing started',
      caseId,
      stepCount: tasks.length / 2,
      movementDataUpdated: true, 
      status: 'PROCESSING',
    };
  }

  // Private Helper cho Worker Logic
  private async runBackgroundConversion(
    tasks: ConversionTaskWithMeta[],
    caseId: string,
    extractPath: string,
    zipFilePath: string,
  ) {
    let completed = 0;
    const total = tasks.length;

    const promises = tasks.map(async (task) => {
      try {
        const result = await this.pool.run(task);
        completed++;
        const filename = this.storage.getBasename(result.path);

        this.dentalGateway.notifyProgress(caseId, {
          status: 'progress',
          file: task.baseName,
          percent: Math.round((completed / total) * 100),
          url: `${this.appUrl}/models/${caseId}/${task.meta.type}/${filename}`,
          type: task.meta.type,
          index: task.meta.index,
        });
      } catch (error: any) {
        this.logger.error(`Error converting ${task.baseName}`, error);
        this.dentalGateway.notifyProgress(caseId, {
          status: 'error',
          file: task.baseName,
          error: error.message,
        });
      }
    });

    await Promise.allSettled(promises);
    this.dentalGateway.notifyComplete(caseId, { status: 'completed' });
    this.logger.info(`Case ${caseId} processing completed.`);

    // Cleanup
    await this.storage.remove(extractPath);
    await this.storage.remove(zipFilePath);
  }
}
