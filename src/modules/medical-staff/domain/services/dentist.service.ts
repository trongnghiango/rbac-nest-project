import { Injectable, Inject } from '@nestjs/common';
import { IDentistRepository } from '../repositories/dentist.repository';
import { CreateDentistDto } from '../../application/dtos/dentist.dto';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DentistService {
  constructor(
    @Inject(IDentistRepository) private readonly repo: IDentistRepository,
  ) {}

  async ensureDentistExists(
    fullName: string,
    clinicId: number,
    tx?: Transaction,
  ): Promise<{ id: number }> {
    const existing = await this.repo.findDentist(fullName, clinicId, tx);
    if (existing) {
      return existing;
    }

    const newDentist: CreateDentistDto = {
      fullName,
      clinicId,
    };

    return this.repo.createDentist(newDentist, tx);
  }
}
