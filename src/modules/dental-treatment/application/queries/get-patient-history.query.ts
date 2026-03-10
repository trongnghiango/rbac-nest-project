import { Injectable, Inject } from '@nestjs/common';
import { IOrthoRepository } from '../../domain/repositories/ortho.repository';
import { CaseHistoryDTO } from '../../domain/types/dental.types';

@Injectable()
export class GetPatientHistoryQuery {
  constructor(
    @Inject(IOrthoRepository) private readonly repo: IOrthoRepository,
  ) {}

  async execute(patientCode: string): Promise<CaseHistoryDTO[]> {
    return this.repo.findCasesByPatientCode(patientCode);
  }
}
