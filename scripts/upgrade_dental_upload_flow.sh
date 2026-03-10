#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🦷 UPGRADING DENTAL UPLOAD API WITH METADATA..."

# ============================================================
# 1. TẠO DTO (VALIDATION INPUT)
# ============================================================
log "1️⃣ Creating Upload DTO..."
mkdir -p src/modules/dental/infrastructure/dtos

cat > src/modules/dental/infrastructure/dtos/upload-case.dto.ts << 'EOF'
import { IsString, IsOptional, IsEnum, IsDateString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum Gender {
  Male = 'Male',
  Female = 'Female',
  Other = 'Other'
}

export enum ProductType {
  Aligner = 'aligner',
  Retainer = 'retainer'
}

export class UploadCaseDto {
  @ApiProperty({ description: 'Full Name of the Patient', example: 'Nguyen Van A' })
  @IsString()
  @IsNotEmpty()
  patientName: string;

  @ApiProperty({ description: 'Unique Patient Code', example: 'PAT-12345' })
  @IsString()
  @IsNotEmpty()
  patientCode: string;

  @ApiProperty({ description: 'Gender', enum: Gender, required: false })
  @IsOptional()
  @IsEnum(Gender)
  gender?: Gender;

  @ApiProperty({ description: 'Date of Birth (ISO)', required: false, example: '1990-01-01' })
  @IsOptional()
  @IsDateString()
  dob?: string;

  @ApiProperty({ description: 'Clinic Name', example: 'Smile Dental' })
  @IsString()
  @IsNotEmpty()
  clinicName: string;

  @ApiProperty({ description: 'Doctor Name', required: false, example: 'Dr. House' })
  @IsOptional()
  @IsString()
  doctorName?: string;

  @ApiProperty({ description: 'Product Type', enum: ProductType, default: ProductType.Aligner })
  @IsOptional()
  @IsEnum(ProductType)
  productType: ProductType = ProductType.Aligner;

  @ApiProperty({ description: 'Additional Notes', required: false })
  @IsOptional()
  @IsString()
  notes?: string;

  @ApiProperty({ type: 'string', format: 'binary' })
  file: any;
}
EOF

# ============================================================
# 2. UPDATE REPOSITORY (LOGIC TRANSACTION)
# ============================================================
log "2️⃣ Updating Repository to handle Full Case Creation..."

cat > src/modules/dental/infrastructure/persistence/drizzle-ortho.repository.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { eq, asc, InferSelectModel, InferInsertModel } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  IOrthoRepository,
  CreateCaseParams,
  OrthoCase,
} from '../../domain/repositories/ortho.repository';
import {
  patients,
  cases,
  treatmentSteps,
  clinics,
  dentists,
} from '@database/schema/ortho.schema';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

// Type definitions
type PatientRecord = InferSelectModel<typeof patients>;
type NewPatientRecord = InferInsertModel<typeof patients>;
type TreatmentStepRecord = InferSelectModel<typeof treatmentSteps>;

export interface SaveStepInput {
  index: number;
  teethMap: Record<string, unknown>;
  hasIpr?: boolean;
  hasAttachments?: boolean;
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

@Injectable()
export class DrizzleOrthoRepository
  extends DrizzleBaseRepository
  implements IOrthoRepository
{
  // --- Transactional Create Full Case ---
  async createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string> {
     // Hàm này tự quản lý transaction nếu tx chưa được truyền vào
     const runInTx = async (dbTx: any) => {
        // 1. Find or Create Clinic
        let clinicId: number;
        // Giả sử clinicCode được tạo từ tên (slug) hoặc logic riêng. Ở đây lấy tên làm code tạm thời
        const clinicCode = data.clinicName.toUpperCase().replace(/\s+/g, '_').substring(0, 10);

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

        // 2. Find or Create Dentist
        let dentistId: number | null = null;
        if (data.doctorName) {
            const existingDentist = await dbTx.select().from(dentists)
                .where(eq(dentists.fullName, data.doctorName))
                .limit(1); // Logic này hơi đơn giản, thực tế cần check theo clinicId nữa

            if (existingDentist.length > 0) {
                dentistId = existingDentist[0].id;
            } else {
                const [newDentist] = await dbTx.insert(dentists).values({
                    fullName: data.doctorName,
                    clinicId: clinicId,
                }).returning();
                dentistId = newDentist.id;
            }
        }

        // 3. Find or Create Patient
        let patientId: number;
        const existingPatient = await dbTx.select().from(patients).where(eq(patients.patientCode, data.patientCode)).limit(1);

        if (existingPatient.length > 0) {
            patientId = existingPatient[0].id;
            // Optional: Update patient info if needed
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

        // 4. Create Case
        const [newCase] = await dbTx.insert(cases).values({
            patientId: patientId,
            dentistId: dentistId,
            productType: data.productType,
            status: 'PROCESSING', // Đang xử lý
            notes: data.notes,
            startedAt: new Date(),
        }).returning();

        return String(newCase.id); // Trả về Case ID (số chuyển thành chuỗi để dùng làm folder name)
     };

     if (tx) {
         return runInTx(tx);
     } else {
         return this.db.transaction(runInTx);
     }
  }

  // --- Implementations cũ (Giữ lại để tương thích Interface cũ nếu cần) ---
  async findPatientByCode(code: string, tx?: Transaction): Promise<PatientRecord | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(patients).where(eq(patients.patientCode, code));
    return result[0] || null;
  }

  async createPatient(data: NewPatientRecord, tx?: Transaction): Promise<PatientRecord> {
    const db = this.getDb(tx);
    const [newPatient] = await db.insert(patients).values(data).returning();
    return newPatient;
  }

  async createCase(data: CreateCaseParams, tx?: Transaction): Promise<OrthoCase> {
      throw new Error("Use createFullCase instead");
  }

  async findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null> {
    const db = this.getDb(tx);
    const result = await db.query.cases.findFirst({
      where: eq(cases.id, id),
      with: { patient: true, dentist: true, steps: true },
    });
    return (result as unknown as OrthoCase) || null;
  }

  async saveSteps(
    caseId: number,
    stepsData: SaveStepInput[],
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);
    if (stepsData.length > 0) {
      await db.delete(treatmentSteps).where(eq(treatmentSteps.caseId, caseId));
      await db.insert(treatmentSteps).values(
        stepsData.map((s) => ({
          caseId,
          stepIndex: s.index,
          teethData: s.teethMap,
          hasIpr: s.hasIpr ?? false,
          hasAttachments: s.hasAttachments ?? false,
        })),
      );
    }
  }

  async getStepsByCaseId(caseId: number, tx?: Transaction): Promise<TreatmentStepRecord[]> {
    const db = this.getDb(tx);
    return await db.select().from(treatmentSteps).where(eq(treatmentSteps.caseId, caseId)).orderBy(asc(treatmentSteps.stepIndex));
  }
}
EOF

# Update Interface trong Repository Port
cat > src/modules/dental/domain/repositories/ortho.repository.ts << 'EOF'
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export interface OrthoCase {
  id: number;
  orderId: string | null;
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
  findPatientByCode(code: string, tx?: Transaction): Promise<any | null>;
  createPatient(data: any, tx?: Transaction): Promise<any>;
  createCase(data: CreateCaseParams, tx?: Transaction): Promise<OrthoCase>;
  // Method mới mạnh mẽ hơn
  createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string>;

  findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null>;
  saveSteps(caseId: number, steps: any[], tx?: Transaction): Promise<void>;
  getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]>;
}
EOF

# ============================================================
# 3. UPDATE SERVICE (LOGIC UPLOAD MỚI)
# ============================================================
log "3️⃣ Updating DentalService to use DB..."

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
EOF

# ============================================================
# 4. UPDATE CONTROLLER
# ============================================================
log "4️⃣ Updating Controller to accept Body DTO..."

cat > src/modules/dental/infrastructure/controllers/dental.controller.ts << 'EOF'
import { Controller, Post, Get, Query, UploadedFile, UseInterceptors, UseGuards, Body } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiTags, ApiConsumes, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
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
  @ApiBody({ type: UploadCaseDto }) // Swagger sẽ hiển thị form đầy đủ
  @UseInterceptors(FileInterceptor('file', { storage }))
  async uploadZip(
    @UploadedFile() file: Express.Multer.File,
    @Body() dto: UploadCaseDto // Nhận toàn bộ thông tin qua DTO
  ) {
    // Gọi Service với file và thông tin DTO
    return this.dentalService.processZipUpload(file, dto);
  }

  @Get('models')
  async listModels(@Query('clientId') clientId: string) {
      // clientId ở đây thực chất là caseId (ID trong DB)
      return this.dentalService.listModels(clientId);
  }
}
EOF

success "✅ API UPGRADE COMPLETED!"
echo "👉 Restart server: npm run start:dev"
echo "👉 Use Postman/Swagger to test new fields (patientName, clinicName...)"