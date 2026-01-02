import { Injectable, Inject } from '@nestjs/common';
import { IOrthoRepository } from '../../domain/repositories/ortho.repository';
import { CaseDetailsDTO } from '../../domain/repositories/ortho.repository'; // Import DTO từ Repo hoặc Types tùy definition

@Injectable()
export class GetCaseDetailsQuery {
  constructor(
    @Inject(IOrthoRepository) private readonly repo: IOrthoRepository,
  ) {}

  async execute(
    clientId: string,
    caseId?: string,
  ): Promise<CaseDetailsDTO | null> {
    const id = caseId || (await this.repo.findLatestCaseIdByCode(clientId));
    return id ? this.repo.getCaseDetails(id, true) : null;
  }
}
