// src/modules/accounting/application/listeners/finote-created.listener.ts
import { Injectable, Inject } from '@nestjs/common';
import { EventHandler } from '@core/shared/infrastructure/event-bus/decorators/event-handler.decorator';
import { FinoteCreatedEvent } from '../../domain/events/finote-created.event';
import { IDocumentGenerator } from '../ports/document-generator.port';
import { IFileStorage } from '../ports/file-storage.port';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { eq } from 'drizzle-orm';
import { TargetResolverFactory } from '../strategies/target-resolver/target-resolver.factory'; // Bổ sung

@Injectable()
export class FinoteCreatedListener {
    constructor(
        @Inject(IDocumentGenerator) private pdfGenerator: IDocumentGenerator,
        @Inject(IFileStorage) private fileStorage: IFileStorage,
        @Inject(LOGGER_TOKEN) private logger: ILogger,
        @Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>,
        private targetResolverFactory: TargetResolverFactory, // Tiêm Factory vào
    ) { }

    @EventHandler(FinoteCreatedEvent)
    async handleFinoteCreated(event: FinoteCreatedEvent) {
        const { finoteId, code, title, amount, type } = event.payload;

        try {
            // 1. LẤY TÊN BẰNG FACTORY STRATEGY (KHÔNG CÒN IF-ELSE) ✨✨✨
            const targetName = await this.targetResolverFactory.resolve(type, event.payload, this.db);

            const finote = await this.db.query.finotes.findFirst({ where: eq(schema.finotes.id, finoteId) });

            // 2. Data cho Template
            const templateData = {
                invoiceCode: code,
                date: new Date().toLocaleDateString('vi-VN'),
                deadlineDate: finote ? finote.deadline_at.toLocaleDateString('vi-VN') : 'N/A',
                title: title,
                category: finote ? finote.category : 'N/A',
                targetName: targetName, // Kết quả từ Strategy
                amountFormatted: new Intl.NumberFormat('vi-VN', { style: 'currency', currency: 'VND' }).format(Number(amount)),
                isExpense: type === 'EXPENSE'
            };

            // 3. Tạo PDF và Lưu (Giữ nguyên như cũ)
            const pdfBuffer = await this.pdfGenerator.generatePdfFromHtml('finote-template', templateData);
            const fileName = `finote_${code}_${Date.now()}.pdf`;
            const fileUrl = await this.fileStorage.uploadBuffer(fileName, pdfBuffer, 'application/pdf');

            await this.db.insert(schema.finoteAttachments).values({
                finote_id: finoteId,
                file_name: fileName,
                google_drive_id: `SYS-GEN-${Date.now()}`,
                web_view_link: fileUrl,
                mime_type: 'application/pdf',
                file_size: pdfBuffer.length,
            });

        } catch (error) {
            this.logger.error(`❌ Lỗi khi tạo PDF:`, error as Error);
        }
    }
}