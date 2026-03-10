import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { IOrthoRepository, CaseDetailsDTO } from '../../domain/repositories/ortho.repository';

// ✅ Định nghĩa kiểu tìm kiếm rõ ràng (Export để nơi khác dùng được)
export type CaseSearchType = 'CaseId' | 'PatientCode';

@Injectable()
export class GetCaseDetailsQuery {
  constructor(
    @Inject(IOrthoRepository) private readonly repo: IOrthoRepository,
  ) { }

  async execute(
    keyword: string,
    searchType: CaseSearchType = 'PatientCode' // ✅ Mặc định là tìm theo PatientCode
  ): Promise<CaseDetailsDTO | null> {

    let targetId: number | null = null;

    // 1. Logic tìm theo Case ID
    if (searchType === 'CaseId') {
      targetId = Number(keyword);
      if (isNaN(targetId)) {
        throw new BadRequestException(`Case ID phải là số, nhận được: ${keyword}`);
      }
    }
    // 2. Logic tìm theo Patient Code
    else if (searchType === 'PatientCode') {
      targetId = await this.repo.findLatestCaseIdByPatientCode(keyword);
    }

    if (!targetId) {
      return null;
    }

    // 3. Query chi tiết
    return this.repo.findCaseDetailById(targetId);
  }
}