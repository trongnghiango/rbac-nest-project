import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Piscina from 'piscina';
import { v4 as uuidv4 } from 'uuid';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';
import { PISCINA_POOL } from '../../infrastructure/workers/piscina.provider';
import { IOrthoRepository } from '../../domain/repositories/ortho.repository';
import { UploadCaseDto } from '../../infrastructure/dtos/upload-case.dto';
import { parseMovementData } from '../utils/movement.parser';
import { DentalGateway } from '../../infrastructure/gateways/dental.gateway';
import {
  ITransactionManager,
  Transaction,
} from '@core/shared/application/ports/transaction-manager.port';
import { IDentalStorage } from '../../domain/ports/dental-storage.port';
import { ConversionBinaries } from '../../domain/ports/dental-worker.port';
import {
  TeethMovementRecord,
  ConversionTaskWithMeta,
  JawType,
  CaseHistoryDTO,
} from '../../domain/types/dental.types';

export interface ModelStep {
  index: number;
  maxillary: string | null;
  mandibular: string | null;
  teethData?: TeethMovementRecord; // ✅ Update type safety here
}

@Injectable()
export class DentalService {
  private readonly appUrl: string;

  constructor(
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    @Inject(PISCINA_POOL) private readonly pool: Piscina,
    @Inject(IOrthoRepository) private readonly orthoRepo: IOrthoRepository,
    @Inject(ITransactionManager)
    private readonly txManager: ITransactionManager,
    @Inject(IDentalStorage) private readonly storage: IDentalStorage,
    private readonly config: ConfigService,
    private readonly dentalGateway: DentalGateway,
  ) {
    this.appUrl = (process.env.APP_URL || 'http://localhost:8080').replace(
      /\/$/,
      '',
    );
    this.storage.ensureDirectories();
  }

  async processZipUpload(file: Express.Multer.File, dto: UploadCaseDto) {
    if (!file) throw new BadRequestException('No file uploaded');

    const isOverwrite = String(dto.overwrite) === 'true';
    let caseId: string | null = null;

    if (isOverwrite) {
      caseId = await this.orthoRepo.findLatestCaseIdByCode(dto.patientCode);
      if (caseId) {
        this.logger.warn(`Cleaning Case ${caseId} for overwrite`);
        const caseDir = this.storage.joinPath(this.storage.outputDir, caseId);
        await this.storage.remove(caseDir);
        await this.orthoRepo.deleteStepsByCaseId(Number(caseId));
      }
    }

    if (!caseId) {
      caseId = await this.txManager.runInTransaction(
        async (tx: Transaction) => {
          const clinicCode = dto.clinicName
            .toUpperCase()
            .replace(/\s+/g, '_')
            .substring(0, 10);
          let clinic = await this.orthoRepo.findClinicByCode(clinicCode, tx);
          if (!clinic) {
            clinic = await this.orthoRepo.createClinic(
              { name: dto.clinicName, code: clinicCode },
              tx,
            );
          }

          let dentistId: number | undefined;
          if (dto.doctorName) {
            let dentist = await this.orthoRepo.findDentist(
              dto.doctorName,
              clinic.id,
              tx,
            );
            if (!dentist) {
              dentist = await this.orthoRepo.createDentist(
                { fullName: dto.doctorName, clinicId: clinic.id },
                tx,
              );
            }
            dentistId = dentist.id;
          }

          let patient = await this.orthoRepo.findPatientByCode(
            dto.patientCode,
            tx,
          );
          if (!patient) {
            const dobDate = dto.dob ? new Date(dto.dob) : undefined;
            patient = await this.orthoRepo.createPatient(
              {
                fullName: dto.patientName,
                patientCode: dto.patientCode,
                clinicId: clinic.id,
                gender: dto.gender,
                dob: dobDate,
              },
              tx,
            );
          }

          const newCase = await this.orthoRepo.createCase(
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

    const extractPath = this.storage.joinPath(
      this.storage.uploadDir,
      `extract_${uuidv4()}`,
    );

    try {
      await this.storage.extractZip(file.path, extractPath);
    } catch (e: any) {
      throw new BadRequestException('Invalid Zip File: ' + e.message);
    }

    const objFiles = await this.storage.findFilesRecursively(
      extractPath,
      '.obj',
    );

    // ✅ REFACTOR: Strict type for binaries config
    const binariesConfig: ConversionBinaries = {
      obj2gltf: this.config.get<string>('dental.binaries.obj2gltf')!,
      gltfPipeline: this.config.get<string>('dental.binaries.gltfPipeline')!,
      gltfTransform: this.config.get<string>('dental.binaries.gltfTransform')!,
    };

    // ✅ REFACTOR: Using defined Type instead of any[]
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

      // Create Job with strictly typed Metadata
      const job: ConversionTaskWithMeta = {
        objFilePath: objPath,
        outputDir: this.storage.joinPath(this.storage.outputDir, caseId!, type),
        baseName: `${type}_${index.toString().padStart(3, '0')}`,
        encryptionKey: this.config.get<string>('dental.encryptionKey')!,
        config: { ratio: 0.3, threshold: 0.0005, timeout: 300000 },
        binaries: binariesConfig,
        meta: { index, type },
      };
      return job;
    });

    this.logger.info(
      `Queueing ${tasks.length} conversion tasks for Case ${caseId}`,
    );
    this.runBackgroundConversion(tasks, caseId!, extractPath, file.path);

    return {
      success: true,
      message: 'Processing started in background',
      caseId,
      stepCount: tasks.length / 2,
      status: 'PROCESSING',
    };
  }

  private async runBackgroundConversion(
    tasks: ConversionTaskWithMeta[], // ✅ REFACTOR: Strict Type
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
        // We assume result has path (handled in worker)
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

    await this.storage.remove(extractPath);
    await this.storage.remove(zipFilePath);
  }

  async processMovementData(file: Express.Multer.File, caseId: string) {
    const fileBuffer = await this.storage.readFile(file.path);

    // ✅ REFACTOR: parseMovementData now returns Map<number, TeethMovementRecord>
    const stepsDataMap = parseMovementData(fileBuffer, file.originalname);

    let count = 0;
    for (const [stepIndex, teethData] of stepsDataMap.entries()) {
      // ✅ REFACTOR: Calls repo with strictly typed record
      await this.orthoRepo.updateStepMovementData(
        caseId,
        stepIndex,
        teethData, // This is now TeethMovementRecord, not any
      );
      count++;
    }

    await this.storage.remove(file.path);
    return {
      message: 'Movement data updated successfully',
      stepsCount: stepsDataMap.size,
      details: `Parsed ${count} steps from file.`,
    };
  }

  async listModels(clientId: string, caseId?: string): Promise<ModelStep[]> {
    const id =
      caseId || (await this.orthoRepo.findLatestCaseIdByCode(clientId));
    if (!id) return [];

    const clientDir = this.storage.joinPath(this.storage.outputDir, id);
    const exists = await this.storage.exists(clientDir);
    const allEncFiles = exists
      ? await this.storage.findFilesRecursively(clientDir, '.enc')
      : [];

    // Note: getStepsByCaseId still returns generic object,
    // ideally repo should return TreatmentStep Entity
    const dbSteps = await this.orthoRepo.getStepsByCaseId(Number(id));
    const stepsMap = new Map<number, ModelStep>();

    dbSteps.forEach((s) => {
      stepsMap.set(s.stepIndex, {
        index: s.stepIndex,
        maxillary: null,
        mandibular: null,
        teethData: s.teethData as TeethMovementRecord, // Type assertion if needed
      });
    });

    allEncFiles.forEach((fp) => {
      const filename = this.storage.getBasename(fp).toLowerCase();
      const matches = filename.match(/(\d+)/g);
      const index = matches ? parseInt(matches[matches.length - 1], 10) : 0;
      const relPath = this.storage.getRelativePath(this.storage.outputDir, fp);
      const url = `${this.appUrl}/models/${relPath}`;

      if (!stepsMap.has(index)) {
        stepsMap.set(index, { index, maxillary: null, mandibular: null });
      }
      const entry = stepsMap.get(index)!;
      if (filename.includes('maxillary')) entry.maxillary = url;
      else if (filename.includes('mandibular')) entry.mandibular = url;
    });

    return Array.from(stepsMap.values()).sort((a, b) => a.index - b.index);
  }

  async getCaseDetails(clientId: string, caseId?: string) {
    const id =
      caseId || (await this.orthoRepo.findLatestCaseIdByCode(clientId));
    return id ? this.orthoRepo.getCaseDetails(id, true) : null;
  }

  // ✅ REFACTOR: Explicit return type
  async getHistory(patientCode: string): Promise<CaseHistoryDTO[]> {
    return this.orthoRepo.findCasesByPatientCode(patientCode);
  }
}
