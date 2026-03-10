import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { IOrthoRepository } from '../../domain/repositories/ortho.repository';
import { IDentalStorage } from '../../domain/ports/dental-storage.port';
import { parseMovementData } from '../utils/movement.parser';

@Injectable()
export class ProcessMovementDataUseCase {
  constructor(
    @Inject(IOrthoRepository) private readonly repo: IOrthoRepository,
    @Inject(IDentalStorage) private readonly storage: IDentalStorage,
  ) {}

  async execute(file: Express.Multer.File, caseId: string) {
    if (!file) throw new BadRequestException('File is required');

    // 1. Đọc file từ ổ đĩa (do Multer đã lưu tạm)
    const fileBuffer = await this.storage.readFile(file.path);

    // 2. Parse dữ liệu (Logic này nằm trong utility function đã có)
    const stepsDataMap = parseMovementData(fileBuffer, file.originalname);

    // 3. Lưu vào DB từng bước
    let count = 0;
    for (const [stepIndex, teethData] of stepsDataMap.entries()) {
      await this.repo.updateStepMovementData(caseId, stepIndex, teethData);
      count++;
    }

    // 4. Xóa file tạm
    await this.storage.remove(file.path);

    return {
      success: true,
      message: 'Movement data updated successfully',
      stepsCount: stepsDataMap.size,
      details: `Parsed ${count} steps from file.`,
    };
  }
}
