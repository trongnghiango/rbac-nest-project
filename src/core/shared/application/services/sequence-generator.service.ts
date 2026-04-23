// src/core/shared/application/services/sequence-generator.service.ts
import { Injectable, Inject } from '@nestjs/common';
import { ISequenceRepository } from '../../domain/repositories/sequence.repository';

export interface SequenceOptions {
    padLength?: number;       // Độ dài số 0 đứng trước. VD: 4 -> 0001
    resetYearly?: boolean;    // Có reset về 1 mỗi năm không? (Mặc định: true)
    resetMonthly?: boolean;   // Có reset về 1 mỗi tháng không? (Mặc định: false)
}

@Injectable()
export class SequenceGeneratorService {
    constructor(
        @Inject(ISequenceRepository) private readonly sequenceRepo: ISequenceRepository,
    ) { }

    /**
     * Sinh mã tự động an toàn trong môi trường concurrent.
     * @param basePrefix Tiền tố cơ sở (Vd: 'INC', 'EXP', 'EMP', 'CON')
     * @param tx Bắt buộc truyền Transaction vào để đảm bảo tính ACID
     * @param options Cấu hình format
     */
    async generateCode(basePrefix: string, options?: SequenceOptions): Promise<string> {
        const now = new Date();
        const year = now.getFullYear().toString();
        const month = (now.getMonth() + 1).toString().padStart(2, '0');

        // 1. Cấu hình mặc định
        const padLength = options?.padLength ?? 4;
        const isResetYearly = options?.resetYearly ?? true;
        const isResetMonthly = options?.resetMonthly ?? false;

        // 2. Xây dựng chuỗi Prefix lưu vào DB (Mẹo để auto-reset)
        // Nếu reset yearly: DB sẽ lưu 'INC-2026'. Sang năm, nó tìm 'INC-2027' không thấy -> tự tạo lại bằng 1.
        let dbPrefix = basePrefix;
        if (isResetYearly) dbPrefix += `-${year}`;
        if (isResetMonthly) dbPrefix += `${month}`; // Thành INC-202604

        // 3. Tăng biến đếm trong DB an toàn
        const nextVal = await this.sequenceRepo.incrementAndGetNext(dbPrefix);

        // 4. Format số (VD: 1 -> 0001)
        const numStr = nextVal.toString().padStart(padLength, '0');

        // 5. Trả về mã cuối cùng
        return `${dbPrefix}-${numStr}`;
    }
}
