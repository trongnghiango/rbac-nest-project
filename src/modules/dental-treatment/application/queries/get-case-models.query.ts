import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IOrthoRepository } from '../../domain/repositories/ortho.repository';
import { IDentalStorage } from '../../domain/ports/dental-storage.port';
import { ModelStep, TeethMovementRecord } from '../../domain/types/dental.types';

@Injectable()
export class GetCaseModelsQuery {
  private readonly appUrl: string;

  constructor(
    @Inject(IOrthoRepository) private readonly repo: IOrthoRepository,
    @Inject(IDentalStorage) private readonly storage: IDentalStorage,
    private readonly config: ConfigService,
  ) {
    this.appUrl = (process.env.APP_URL || 'http://localhost:8080').replace(/\/$/, '');
  }

  async execute(patientCode: string, caseId?: string): Promise<ModelStep[]> {
    let targetId: number | null = null;

    // 1. Resolve Target Case ID
    if (caseId) {
      targetId = Number(caseId);
      if (isNaN(targetId)) throw new BadRequestException('Invalid Case ID');
    } else {
      targetId = await this.repo.findLatestCaseIdByPatientCode(patientCode);
    }

    if (!targetId) return [];

    const idStr = String(targetId); // Cần string cho đường dẫn file

    // 2. Scan Files from Storage
    const clientDir = this.storage.joinPath(this.storage.outputDir, idStr);
    const exists = await this.storage.exists(clientDir);
    const allEncFiles = exists
      ? await this.storage.findFilesRecursively(clientDir, '.enc')
      : [];

    // 3. Get Steps Logic from DB
    const dbSteps = await this.repo.getStepsByCaseId(targetId);
    const stepsMap = new Map<number, ModelStep>();

    // 4. Map DB Data
    dbSteps.forEach((s) => {
      stepsMap.set(s.stepIndex, {
        index: s.stepIndex,
        maxillary: null,
        mandibular: null,
        teethData: s.teethData as TeethMovementRecord,
      });
    });

    // 5. Map File System Data
    allEncFiles.forEach((fp) => {
      const filename = this.storage.getBasename(fp).toLowerCase();
      const matches = filename.match(/(\d+)/g);
      const index = matches ? parseInt(matches[matches.length - 1], 10) : 0;
      const relPath = this.storage.getRelativePath(this.storage.outputDir, fp);
      // Sử dụng encodeURIComponent để đảm bảo URL an toàn
      const url = `${this.appUrl}/models/${relPath.split('/').map(encodeURIComponent).join('/')}`;

      if (!stepsMap.has(index)) {
        stepsMap.set(index, { index, maxillary: null, mandibular: null });
      }
      const entry = stepsMap.get(index)!;
      if (filename.includes('maxillary')) entry.maxillary = url;
      else if (filename.includes('mandibular')) entry.mandibular = url;
    });

    return Array.from(stepsMap.values()).sort((a, b) => a.index - b.index);
  }
}
