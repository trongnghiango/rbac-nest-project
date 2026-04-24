// src/modules/accounting/application/services/finote-document.service.ts
import { Injectable, Inject } from '@nestjs/common';
import { IDocumentGenerator } from '../ports/document-generator.port';
import { IFileStorage } from '../ports/file-storage.port';
import { IFinoteRepository } from '../../domain/repositories/finote.repository';
import { TargetResolverFactory } from '../strategies/target-resolver/target-resolver.factory';

@Injectable()
export class FinoteDocumentService {
    constructor(
        @Inject(IDocumentGenerator) private readonly pdfGenerator: IDocumentGenerator,
        @Inject(IFileStorage) private readonly fileStorage: IFileStorage,
        @Inject(IFinoteRepository) private readonly finoteRepo: IFinoteRepository,
        private readonly targetResolverFactory: TargetResolverFactory,
    ) { }

    async generateAndAttachPdf(finoteId: number, eventPayload: any): Promise<void> {
        const targetName = await this.targetResolverFactory.resolve(eventPayload.type, eventPayload);
        const finote = await this.finoteRepo.findById(finoteId);

        if (!finote) throw new Error(`Finote ${finoteId} not found`);

        const templateData = {
            invoiceCode: finote.code,
            date: new Date().toLocaleDateString('vi-VN'),
            deadlineDate: finote.deadlineAt ? finote.deadlineAt.toLocaleDateString('vi-VN') : 'N/A',
            title: finote.title,
            category: finote.category,
            targetName: targetName,
            amountFormatted: finote.amount.formatVND(), // Sử dụng tiện ích của VO
            isExpense: finote.type === 'EXPENSE'
        };

        const pdfBuffer = await this.pdfGenerator.generatePdfFromHtml('finote-template', templateData);
        const fileName = `finote_${finote.code}_${Date.now()}.pdf`;
        const fileUrl = await this.fileStorage.uploadBuffer(fileName, pdfBuffer, 'application/pdf');

        await this.finoteRepo.addAttachment({
            finote_id: finoteId,
            file_name: fileName,
            google_drive_id: `SYS-GEN-${Date.now()}`,
            web_view_link: fileUrl,
            mime_type: 'application/pdf',
            file_size: pdfBuffer.length,
        });
    }
}
