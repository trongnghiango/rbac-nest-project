import { Injectable, Inject } from '@nestjs/common';
import { IClinicRepository } from '../repositories/clinic.repository';
import { CreateClinicDto } from '../../application/dtos/clinic.dto';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class ClinicService {
  constructor(
    @Inject(IClinicRepository) private readonly repo: IClinicRepository,
  ) {}

  /**
   * Tìm Clinic theo code, nếu chưa có thì tạo mới.
   * Logic chuẩn hóa mã code được thực hiện ở đây.
   */
  async ensureClinicExists(
    name: string,
    rawCode?: string,
    tx?: Transaction,
  ): Promise<{ id: number }> {
    // Business Rule: Auto-generate code if missing
    const code =
      rawCode || name.toUpperCase().replace(/\s+/g, '_').substring(0, 10);

    const existing = await this.repo.findClinicByCode(code, tx);
    if (existing) {
      return existing;
    }

    const newClinic: CreateClinicDto = {
      name,
      clinicCode: code,
    };

    return this.repo.createClinic(newClinic, tx);
  }
}
