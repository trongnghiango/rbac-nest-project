// src/modules/accounting/application/listeners/finote-created.listener.ts
import { Injectable, Inject } from '@nestjs/common';
import { EventHandler } from '@core/shared/infrastructure/event-bus/decorators/event-handler.decorator';
import { FinoteCreatedEvent } from '../../domain/events/finote-created.event';
import { FinoteDocumentService } from '../services/finote-document.service';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';

@Injectable()
export class FinoteCreatedListener {
    constructor(
        private readonly documentService: FinoteDocumentService,
        @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    ) { }

    @EventHandler(FinoteCreatedEvent)
    async handleFinoteCreated(event: FinoteCreatedEvent) {
        try {
            await this.documentService.generateAndAttachPdf(event.payload.finoteId, event.payload);
            this.logger.info(`✅ Đã sinh PDF tự động cho phiếu: ${event.payload.code}`);
        } catch (error) {
            this.logger.error(`❌ Lỗi khi xử lý Event FinoteCreated [${event.payload.code}]:`, error as Error);
        }
    }
}