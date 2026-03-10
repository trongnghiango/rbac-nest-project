#!/bin/bash

# Dừng script nếu có lỗi
set -e

echo "🚀 Bắt đầu Refactoring: Thêm Real-time WebSocket cho Dental Module..."

# 1. Định nghĩa đường dẫn file
GATEWAY_DIR="src/modules/dental/infrastructure/gateways"
GATEWAY_FILE="$GATEWAY_DIR/dental.gateway.ts"
MODULE_FILE="src/modules/dental/dental.module.ts"
SERVICE_FILE="src/modules/dental/application/services/dental.service.ts"

# 2. Backup file cũ (An toàn là trên hết)
BACKUP_DIR="_backup_before_refactor_$(date +%s)"
echo "📦 Đang backup file cũ vào thư mục: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
[ -f "$MODULE_FILE" ] && cp "$MODULE_FILE" "$BACKUP_DIR/"
[ -f "$SERVICE_FILE" ] && cp "$SERVICE_FILE" "$BACKUP_DIR/"

# 3. Cài đặt Dependencies
echo "📦 Đang cài đặt thư viện Socket.io..."
npm install @nestjs/websockets @nestjs/platform-socket.io socket.io

# 4. Tạo thư mục Gateway
mkdir -p "$GATEWAY_DIR"

# 5. Tạo file DentalGateway
echo "📝 Đang tạo file: $GATEWAY_FILE"
cat << 'EOF' > "$GATEWAY_FILE"
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger } from '@nestjs/common';

@WebSocketGateway({
  namespace: 'dental',
  cors: { origin: '*' },
})
export class DentalGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private logger = new Logger(DentalGateway.name);

  handleConnection(client: Socket) {
    this.logger.log(`Client connected: ${client.id}`);
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected: ${client.id}`);
  }

  @SubscribeMessage('join_case')
  handleJoinCase(
    @MessageBody() data: { caseId: string },
    @ConnectedSocket() client: Socket,
  ) {
    const roomName = `case_${data.caseId}`;
    client.join(roomName);
    this.logger.log(`Client ${client.id} joined room: ${roomName}`);
    return { event: 'joined', data: `Joined case ${data.caseId}` };
  }

  notifyProgress(caseId: string, data: any) {
    this.server.to(`case_${caseId}`).emit('conversion_progress', data);
  }

  notifyComplete(caseId: string, data: any) {
    this.server.to(`case_${caseId}`).emit('case_ready', data);
  }
}
EOF

# 6. Cập nhật DentalModule (Thêm Gateway vào providers)
echo "📝 Đang cập nhật: $MODULE_FILE"
cat << 'EOF' > "$MODULE_FILE"
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DentalController } from './infrastructure/controllers/dental.controller';
import { DentalService } from './application/services/dental.service';
import { PiscinaProvider } from './infrastructure/workers/piscina.provider';
import { FileSystemDentalStorage } from './infrastructure/adapters/fs-dental-storage.adapter';
import { PiscinaDentalWorker } from './infrastructure/adapters/piscina-worker.adapter';
import { DrizzleOrthoRepository } from './infrastructure/persistence/drizzle-ortho.repository';
import { IDentalStorage } from './domain/ports/dental-storage.port';
import { IDentalWorker } from './domain/ports/dental-worker.port';
import { IOrthoRepository } from './domain/repositories/ortho.repository';
import { DentalGateway } from './infrastructure/gateways/dental.gateway';
import dentalConfig from '@config/dental.config';

@Module({
  imports: [ConfigModule.forFeature(dentalConfig)],
  controllers: [DentalController],
  providers: [
    DentalService,
    PiscinaProvider,
    DentalGateway, // ✅ Added Gateway
    {
      provide: IDentalStorage,
      useClass: FileSystemDentalStorage,
    },
    {
      provide: IDentalWorker,
      useClass: PiscinaDentalWorker,
    },
    {
      provide: IOrthoRepository,
      useClass: DrizzleOrthoRepository,
    },
  ],
})
export class DentalModule {}
EOF

# 7. Cập nhật DentalService (Logic Pro: Background Task + Socket Emit)
echo "📝 Đang cập nhật: $SERVICE_FILE"
cat << 'EOF' > "$SERVICE_FILE"
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
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment,@typescript-eslint/no-require-imports
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
import { DentalGateway } from '../../infrastructure/gateways/dental.gateway';

export interface ModelStep {
  index: number;
  maxillary: string | null;
  mandibular: string | null;
  teethData?: Record<string, any>;
}

@Injectable()
export class DentalService {
  private readonly uploadDir: string;
  private readonly outputDir: string;
  private readonly appUrl: string;

  constructor(
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    @Inject(PISCINA_POOL) private readonly pool: Piscina,
    @Inject(IOrthoRepository) private readonly orthoRepo: IOrthoRepository,
    private readonly config: ConfigService,
    private readonly dentalGateway: DentalGateway, // ✅ Inject Gateway
  ) {
    this.uploadDir = path.resolve(
      this.config.get('dental.uploadDir') || 'uploads/dental/temp',
    );
    this.outputDir = path.resolve(
      this.config.get('dental.outputDir') || 'uploads/dental/converted',
    );
    this.appUrl = (process.env.APP_URL || 'http://localhost:8080').replace(
      /\/$/,
      '',
    );
    fs.ensureDirSync(this.uploadDir);
    fs.ensureDirSync(this.outputDir);
  }

  async processZipUpload(file: Express.Multer.File, dto: UploadCaseDto) {
    if (!file) throw new BadRequestException('No file uploaded');

    const isOverwrite = String(dto.overwrite) === 'true';
    let caseId: string | null = null;

    if (isOverwrite) {
      caseId = await this.orthoRepo.findLatestCaseIdByCode(dto.patientCode);
      if (caseId) {
        this.logger.warn(`Cleaning Case ${caseId} for overwrite`);
        await fs.remove(path.join(this.outputDir, caseId)).catch(() => {});
        await (this.orthoRepo as any).deleteStepsByCaseId(Number(caseId));
      }
    }

    if (!caseId) {
      caseId = await this.orthoRepo.createFullCase({
        patientName: dto.patientName,
        patientCode: dto.patientCode,
        clinicName: dto.clinicName,
        doctorName: dto.doctorName,
        gender: dto.gender,
        productType: dto.productType,
        notes: dto.notes,
      });
    }

    const extractPath = path.join(this.uploadDir, `extract_${uuidv4()}`);

    // 1. Giải nén ngay lập tức
    try {
      const zip = new AdmZip(file.path);
      zip.extractAllTo(extractPath, true);
    } catch (e: any) {
      throw new BadRequestException('Invalid Zip File: ' + e.message);
    }

    const objFiles = await this.findFilesRecursively(extractPath, '.obj');

    // 2. Chuẩn bị Tasks
    const tasks = objFiles.map((objPath) => {
      const baseName = path.basename(objPath, '.obj');
      const parentDir = path.basename(path.dirname(objPath));

      let type: 'Maxillary' | 'Mandibular' = baseName
        .toLowerCase()
        .includes('mandibular')
        ? 'Mandibular'
        : 'Maxillary';

      let index = 0;
      const folderMatch = parentDir.match(/(\d+)/);
      const fileMatch = baseName.match(/(\d+)/);

      if (folderMatch) index = parseInt(folderMatch[1], 10);
      else if (fileMatch) index = parseInt(fileMatch[1], 10);

      return {
        objFilePath: objPath,
        outputDir: path.join(this.outputDir, caseId!, type),
        baseName: `${type}_${index.toString().padStart(3, '0')}`,
        encryptionKey: this.config.get('dental.encryptionKey'),
        config: { ratio: 0.3, threshold: 0.0005, timeout: 300000 },
        meta: { index, type },
      };
    });

    this.logger.info(
      `Queueing ${tasks.length} conversion tasks for Case ${caseId}`,
    );

    // 3. 🔥 FIRE AND FORGET: Chạy background, không await
    this.runBackgroundConversion(tasks, caseId!, extractPath, file.path);

    // 4. Trả về kết quả ngay lập tức
    return {
      success: true,
      message: 'Processing started in background',
      caseId,
      stepCount: tasks.length / 2,
      status: 'PROCESSING'
    };
  }

  // ✅ Hàm xử lý chạy ngầm và bắn Socket
  private async runBackgroundConversion(
    tasks: any[],
    caseId: string,
    extractPath: string,
    zipFilePath: string
  ) {
    let completed = 0;
    const total = tasks.length;

    // Chạy tuần tự hoặc song song tùy ý, ở đây dùng Promise.allSettled để tối đa hiệu năng
    const promises = tasks.map(async (task) => {
      try {
        const result = await this.pool.run(task);
        completed++;

        // 🔥 Emit Progress Event
        this.dentalGateway.notifyProgress(caseId, {
          status: 'progress',
          file: task.baseName,
          percent: Math.round((completed / total) * 100),
          url: `${this.appUrl}/models/${caseId}/${task.meta.type}/${path.basename(result.path)}`,
          type: task.meta.type,
          index: task.meta.index
        });

      } catch (error: any) {
        this.logger.error(`Error converting ${task.baseName}`, error);
        this.dentalGateway.notifyProgress(caseId, {
            status: 'error',
            file: task.baseName,
            error: error.message
        });
      }
    });

    await Promise.allSettled(promises);

    // 🔥 Emit Complete Event
    this.dentalGateway.notifyComplete(caseId, { status: 'completed' });
    this.logger.info(`Case ${caseId} processing completed.`);

    // Cleanup sau khi xong hết
    await fs.remove(extractPath).catch(() => {});
    await fs.remove(zipFilePath).catch(() => {});
  }

  async processMovementExcel(file: Express.Multer.File, caseId: string) {
    const fileBuffer = await fs.readFile(file.path);
    const stepsDataMap = parseMovementExcel(fileBuffer);
    for (const [stepIndex, teethData] of stepsDataMap.entries()) {
      await this.orthoRepo.updateStepMovementData(caseId, stepIndex, teethData);
    }
    await fs.remove(file.path).catch(() => {});
    return { message: 'Movement data updated', count: stepsDataMap.size };
  }

  async listModels(clientId: string, caseId?: string): Promise<ModelStep[]> {
    const id =
      caseId || (await this.orthoRepo.findLatestCaseIdByCode(clientId));
    if (!id) return [];

    const clientDir = path.join(this.outputDir, id);
    const allEncFiles = fs.existsSync(clientDir)
      ? await this.findFilesRecursively(clientDir, '.enc')
      : [];
    const dbSteps = await this.orthoRepo.getStepsByCaseId(Number(id));

    const stepsMap = new Map<number, ModelStep>();

    dbSteps.forEach((s) => {
      stepsMap.set(s.stepIndex, {
        index: s.stepIndex,
        maxillary: null,
        mandibular: null,
        teethData: s.teethData,
      });
    });

    allEncFiles.forEach((fp) => {
      const filename = path.basename(fp).toLowerCase();
      const matches = filename.match(/(\d+)/g);
      const index = matches ? parseInt(matches[matches.length - 1], 10) : 0;

      const relPath = path
        .relative(this.outputDir, fp)
        .split(path.sep)
        .join('/');
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

  async getHistory(patientCode: string) {
    return this.orthoRepo.findCasesByPatientCode(patientCode);
  }

  private async findFilesRecursively(
    dir: string,
    ext: string,
  ): Promise<string[]> {
    let results: string[] = [];
    if (!fs.existsSync(dir)) return results;
    const list = await fs.readdir(dir);
    for (const file of list) {
      const fullPath = path.resolve(dir, file);
      if (fs.statSync(fullPath).isDirectory()) {
        results = results.concat(
          await this.findFilesRecursively(fullPath, ext),
        );
      } else if (file.toLowerCase().endsWith(ext)) {
        results.push(fullPath);
      }
    }
    return results;
  }
}
EOF

echo "✅ Refactoring hoàn tất! Đã thêm WebSocket và tối ưu Service."
echo "👉 Hãy restart server và test tính năng Real-time."