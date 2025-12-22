#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🦷 FINALIZING DENTAL MODULE (FULL REPO IMPL + HISTORY FEATURE)..."

# ============================================================
# 1. UPDATE REPOSITORY (FULL IMPLEMENTATION)
# ============================================================
log "1️⃣ Implementing FULL Drizzle Repository (No more stubs)..."

cat > src/modules/dental/infrastructure/persistence/drizzle-ortho.repository.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { eq, desc, and } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  IOrthoRepository,
  CreateCaseParams,
  OrthoCase,
  FullCaseInput
} from '../../domain/repositories/ortho.repository';
import {
  patients,
  cases,
  treatmentSteps,
  clinics,
  dentists,
} from '@database/schema/ortho.schema';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleOrthoRepository
  extends DrizzleBaseRepository
  implements IOrthoRepository
{
  // --- Create Full Case (Logic Transaction) ---
  async createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string> {
     const runInTx = async (dbTx: any) => {
        const clinicCode = data.clinicName.toUpperCase().replace(/\s+/g, '_').substring(0, 10);

        // 1. Clinic
        let clinicId: number;
        const existingClinic = await dbTx.select().from(clinics).where(eq(clinics.clinicCode, clinicCode)).limit(1);
        if (existingClinic.length > 0) {
            clinicId = existingClinic[0].id;
        } else {
            const [newClinic] = await dbTx.insert(clinics).values({
                name: data.clinicName,
                clinicCode: clinicCode,
            }).returning();
            clinicId = newClinic.id;
        }

        // 2. Dentist
        let dentistId: number | null = null;
        if (data.doctorName) {
            const [newDentist] = await dbTx.insert(dentists).values({
                fullName: data.doctorName,
                clinicId: clinicId,
            }).returning();
            dentistId = newDentist.id;
        }

        // 3. Patient
        let patientId: number;
        const existingPatient = await dbTx.select().from(patients).where(eq(patients.patientCode, data.patientCode)).limit(1);
        if (existingPatient.length > 0) {
            patientId = existingPatient[0].id;
        } else {
            const [newPatient] = await dbTx.insert(patients).values({
                fullName: data.patientName,
                patientCode: data.patientCode,
                clinicId: clinicId,
                gender: data.gender,
                birthDate: data.dob ? data.dob.toISOString().split('T')[0] : null,
            }).returning();
            patientId = newPatient.id;
        }

        // 4. Case
        const [newCase] = await dbTx.insert(cases).values({
            patientId: patientId,
            dentistId: dentistId,
            productType: data.productType,
            status: 'PROCESSING',
            notes: data.notes,
            startedAt: new Date(),
        }).returning();

        return String(newCase.id);
     };

     if (tx) return runInTx(tx);
     return this.db.transaction(runInTx);
  }

  // --- Tìm Case ID mới nhất ---
  async findLatestCaseIdByCode(code: string, tx?: Transaction): Promise<string | null> {
    const db = this.getDb(tx);

    // Nếu code là số, check xem có phải ID case không
    if (!isNaN(Number(code))) {
        const caseById = await db.query.cases.findFirst({
            where: eq(cases.id, Number(code))
        });
        if (caseById) return String(caseById.id);
    }

    // Tìm theo Patient Code
    const result = await db.select({
        caseId: cases.id
    })
    .from(cases)
    .innerJoin(patients, eq(cases.patientId, patients.id))
    .where(eq(patients.patientCode, code))
    .orderBy(desc(cases.createdAt))
    .limit(1);

    if (result.length > 0) return String(result[0].caseId);
    return null;
  }

  // --- Lấy danh sách lịch sử Case của Patient ---
  async findCasesByPatientCode(patientCode: string, tx?: Transaction): Promise<any[]> {
    const db = this.getDb(tx);

    // Join Patient -> Cases -> Dentist
    const result = await db.select({
        caseId: cases.id,
        status: cases.status,
        createdAt: cases.createdAt,
        notes: cases.notes,
        productType: cases.productType,
        doctorName: dentists.fullName
    })
    .from(cases)
    .innerJoin(patients, eq(cases.patientId, patients.id))
    .leftJoin(dentists, eq(cases.dentistId, dentists.id))
    .where(eq(patients.patientCode, patientCode))
    .orderBy(desc(cases.createdAt));

    return result;
  }

  // --- Legacy Implementation (Fully implemented now) ---

  async findPatientByCode(code: string, tx?: Transaction): Promise<any | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(patients).where(eq(patients.patientCode, code));
    return result[0] || null;
  }

  async createPatient(data: any, tx?: Transaction): Promise<any> {
    const db = this.getDb(tx);
    const [newPatient] = await db.insert(patients).values(data).returning();
    return newPatient;
  }

  async createCase(data: CreateCaseParams, tx?: Transaction): Promise<OrthoCase> {
    const db = this.getDb(tx);
    const [newCase] = await db.insert(cases).values({
        patientId: data.patientId,
        dentistId: data.dentistId,
        productType: data.productType,
        status: 'PLANNING',
        scanDate: data.scanDate || new Date(),
    }).returning();
    return newCase as unknown as OrthoCase;
  }

  async findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null> {
    const db = this.getDb(tx);
    const result = await db.query.cases.findFirst({
        where: eq(cases.id, id),
        with: { patient: true, dentist: true, steps: true }
    });
    return (result as unknown as OrthoCase) || null;
  }

  async saveSteps(caseId: number, stepsData: any[], tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    if (stepsData.length > 0) {
        await db.delete(treatmentSteps).where(eq(treatmentSteps.caseId, caseId));
        await db.insert(treatmentSteps).values(stepsData.map(s => ({
            caseId,
            stepIndex: s.index,
            teethData: s.teethMap,
            hasIpr: s.hasIpr || false,
            hasAttachments: s.hasAttachments || false
        })));
    }
  }

  async getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]> {
    const db = this.getDb(tx);
    return await db.select()
        .from(treatmentSteps)
        .where(eq(treatmentSteps.caseId, caseId))
        .orderBy(asc(treatmentSteps.stepIndex));
  }
}
EOF

# Update Interface Repo
cat > src/modules/dental/domain/repositories/ortho.repository.ts << 'EOF'
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export interface OrthoCase {
  id: number;
  orderId?: string | null;
  patientId: number;
  status: string | null;
  createdAt: Date | null;
}
export interface CreateCaseParams {
  patientId: number;
  dentistId?: number;
  productType: 'aligner' | 'retainer';
  scanDate?: Date;
}
export interface FullCaseInput {
  patientName: string;
  patientCode: string;
  gender?: 'Male' | 'Female' | 'Other';
  dob?: Date;
  clinicName: string;
  doctorName?: string;
  productType: 'aligner' | 'retainer';
  notes?: string;
}

export const IOrthoRepository = Symbol('IOrthoRepository');

export interface IOrthoRepository {
  createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string>;
  findLatestCaseIdByCode(code: string, tx?: Transaction): Promise<string | null>;
  findCasesByPatientCode(patientCode: string, tx?: Transaction): Promise<any[]>; // NEW: History

  findPatientByCode(code: string, tx?: Transaction): Promise<any | null>;
  createPatient(data: any, tx?: Transaction): Promise<any>;
  createCase(data: any, tx?: Transaction): Promise<any>;
  findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null>;
  saveSteps(caseId: number, steps: any[], tx?: Transaction): Promise<void>;
  getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]>;
}
EOF

# ============================================================
# 2. UPDATE SERVICE (HISTORY & LATEST LOGIC)
# ============================================================
log "2️⃣ Updating DentalService (Smart ID Resolution)..."

cat > src/modules/dental/application/services/dental.service.ts << 'EOF'
import { Injectable, Inject, BadRequestException, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Piscina from 'piscina';
import * as fs from 'fs-extra';
import * as path from 'path';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const AdmZip = require('adm-zip');
import { v4 as uuidv4 } from 'uuid';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { PISCINA_POOL } from '../../infrastructure/workers/piscina.provider';
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
    @Inject(IOrthoRepository) private readonly orthoRepo: IOrthoRepository,
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

  async processZipUpload(file: Express.Multer.File, dto: UploadCaseDto) {
    if (!file) throw new BadRequestException('No file uploaded');

    const caseId = await this.orthoRepo.createFullCase({
        patientName: dto.patientName,
        patientCode: dto.patientCode,
        clinicName: dto.clinicName,
        doctorName: dto.doctorName,
        gender: dto.gender,
        productType: dto.productType,
        notes: dto.notes
    });

    this.logger.info(`Processing upload for PatientCode: ${dto.patientCode} -> CaseID: ${caseId}`);

    const jobId = uuidv4();
    const extractPath = path.join(this.uploadDir, `extract_${jobId}`);

    try {
        const zip = new AdmZip(file.path);
        zip.extractAllTo(extractPath, true);

        // Quét đệ quy để tìm tất cả file .obj
        const objFiles = await this.findFilesRecursively(extractPath, '.obj');
        this.logger.info(`Found ${objFiles.length} OBJ files`, { jobId });

        if (objFiles.length === 0) {
            throw new Error("No .obj files found in the zip");
        }

        const tasks = objFiles.map(objPath => {
            const baseName = path.basename(objPath, '.obj');

            // Logic parse Index & Type
            let type: 'Maxillary' | 'Mandibular' = 'Maxillary';
            if (baseName.toLowerCase().includes('mandibular')) type = 'Mandibular';

            // Tìm index từ tên file hoặc thư mục cha
            let index = 0;
            const fileMatch = baseName.match(/(\d+)/);
            // Tìm trong thư mục cha (ví dụ "Subsetup 1")
            const parentDir = path.dirname(objPath);
            const dirMatch = parentDir.match(/(\d+)/);

            if (dirMatch) index = parseInt(dirMatch[1], 10);
            else if (fileMatch) index = parseInt(fileMatch[1], 10);

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
                }
            };
        });

        await Promise.allSettled(tasks.map(t => this.pool.run(t)));

        return {
            message: 'Processing completed',
            caseId: caseId,
            patientCode: dto.patientCode
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

  // ✅ LOGIC 1: Lấy danh sách Models (Mặc định lấy Latest, hoặc theo CaseId cụ thể)
  async listModels(clientIdOrCode: string, specificCaseId?: string): Promise<ModelStep[]> {
      let targetFolder = '';

      if (specificCaseId) {
          // Nếu Frontend yêu cầu rõ ràng 1 Case ID (Lịch sử)
          this.logger.info(`Fetching specific case: ${specificCaseId}`);
          targetFolder = specificCaseId;
      } else {
          // Mặc định: Tìm Case mới nhất của Patient Code này
          this.logger.info(`Resolving latest case for: ${clientIdOrCode}`);
          const latestCaseId = await this.orthoRepo.findLatestCaseIdByCode(clientIdOrCode);

          if (latestCaseId) {
              targetFolder = latestCaseId;
              this.logger.info(`Resolved ${clientIdOrCode} -> Latest CaseID: ${latestCaseId}`);
          } else {
              // Fallback: Tìm folder cũ (Backward compatibility)
              if (fs.existsSync(path.join(this.outputDir, clientIdOrCode))) {
                  targetFolder = clientIdOrCode;
                  this.logger.warn(`Using legacy folder: ${clientIdOrCode}`);
              }
          }
      }

      if (!targetFolder) return [];

      return this.scanFolder(targetFolder);
  }

  // ✅ LOGIC 2: Lấy danh sách lịch sử
  async getHistory(patientCode: string) {
      return this.orthoRepo.findCasesByPatientCode(patientCode);
  }

  private async scanFolder(folderName: string): Promise<ModelStep[]> {
      const clientDir = path.join(this.outputDir, folderName);
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
EOF

# ============================================================
# 3. UPDATE CONTROLLER (ADD HISTORY ENDPOINT)
# ============================================================
log "3️⃣ Updating Controller to expose History..."

cat > src/modules/dental/infrastructure/controllers/dental.controller.ts << 'EOF'
import { Controller, Post, Get, Query, UploadedFile, UseInterceptors, UseGuards, Body } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiTags, ApiConsumes, ApiBody, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { diskStorage } from 'multer';
import * as fs from 'fs-extra';
import { DentalService } from '../../application/services/dental.service';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { UploadCaseDto } from '../dtos/upload-case.dto';

const uploadDir = 'uploads/temp';
try { fs.ensureDirSync(uploadDir); } catch (e) {}

const storage = diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});

@ApiTags('Dental 3D')
@ApiBearerAuth()
@Controller('dental')
@UseGuards(JwtAuthGuard)
export class DentalController {
  constructor(private readonly dentalService: DentalService) {}

  @Post('upload')
  @ApiConsumes('multipart/form-data')
  @ApiBody({ type: UploadCaseDto })
  @UseInterceptors(FileInterceptor('file', { storage }))
  async uploadZip(
    @UploadedFile() file: Express.Multer.File,
    @Body() dto: UploadCaseDto
  ) {
    return this.dentalService.processZipUpload(file, dto);
  }

  @Get('models')
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  @ApiQuery({ name: 'caseId', required: false, description: 'Optional specific Case ID (from history)' })
  async listModels(
    @Query('clientId') clientId: string,
    @Query('caseId') caseId?: string
  ) {
      // Nếu có caseId thì lấy đúng case đó, nếu không thì lấy case mới nhất của clientId
      return this.dentalService.listModels(clientId, caseId);
  }

  @Get('history')
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  async getHistory(@Query('clientId') clientId: string) {
      return this.dentalService.getHistory(clientId);
  }
}
EOF

success "✅ UPGRADE COMPLETE!"
echo "----------------------------------------------------"
echo "👉 1. Restart Backend: npm run start:dev"
echo "👉 2. Default: GET /models?clientId=12341234 (Auto fetches latest case)"
echo "👉 3. History: GET /history?clientId=12341234 (Lists all versions)"
echo "👉 4. Specific: GET /models?clientId=12341234&caseId=1 (Fetches case #1)"
echo "----------------------------------------------------"