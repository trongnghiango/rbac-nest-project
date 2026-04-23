import { Injectable, Inject } from '@nestjs/common';
import { EventHandler } from '@core/shared/infrastructure/event-bus/decorators/event-handler.decorator';
import { FinoteCreatedEvent } from '../../domain/events/finote-created.event';
import { IDocumentGenerator } from '../ports/document-generator.port';
import { IFileStorage } from '../ports/file-storage.port';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { IFinoteRepository } from '../../domain/repositories/finote.repository';
import { TargetResolverFactory } from '../strategies/target-resolver/target-resolver.factory';

@Injectable()
export class FinoteCreatedListener {
    constructor(
        @Inject(IDocumentGenerator) private readonly pdfGenerator: IDocumentGenerator,
        @Inject(IFileStorage) private readonly fileStorage: IFileStorage,
        @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
        @Inject(IFinoteRepository) private readonly finoteRepo: IFinoteRepository, // Dùng Repo
        private readonly targetResolverFactory: TargetResolverFactory,
    ) { }

    @EventHandler(FinoteCreatedEvent)
    async handleFinoteCreated(event: FinoteCreatedEvent) {
        const { finoteId, code, title, amount, type } = event.payload;

        try {
            // 1. Lấy tên đối tượng: Sạch sẽ, không còn rò rỉ 'db'
            const targetName = await this.targetResolverFactory.resolve(type, event.payload);

            // 2. Lấy thông tin phiếu qua Repo
            const finote = await this.finoteRepo.findById(finoteId);

            const templateData = {
                invoiceCode: code,
                date: new Date().toLocaleDateString('vi-VN'),
                deadlineDate: finote?.deadline_at ? finote.deadline_at.toLocaleDateString('vi-VN') : 'N/A',
                title: title,
                category: finote ? finote.category : 'N/A',
                targetName: targetName,
                amountFormatted: finote.amount.formatVND(),
                isExpense: type === 'EXPENSE'
            };

            // 3. Tạo PDF
            const pdfBuffer = await this.pdfGenerator.generatePdfFromHtml('finote-template', templateData);
            const fileName = `finote_${code}_${Date.now()}.pdf`;

            // 4. Lưu File
            const fileUrl = await this.fileStorage.uploadBuffer(fileName, pdfBuffer, 'application/pdf');

            // 5. Cập nhật DB qua Repo
            await this.finoteRepo.addAttachment({
                finote_id: finoteId,
                file_name: fileName,
                google_drive_id: `SYS-GEN-${Date.now()}`,
                web_view_link: fileUrl,
                mime_type: 'application/pdf',
                file_size: pdfBuffer.length,
            });

        } catch (error) {
            this.logger.error(`❌ Lỗi khi xử lý Event FinoteCreated [${code}]:`, error as Error);
        }
    }
}
