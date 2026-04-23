// src/modules/accounting/application/services/finote.service.ts
import { Injectable, Inject } from '@nestjs/common';
import { ITransactionManager, Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { SequenceGeneratorService } from '@core/shared/application/services/sequence-generator.service';
import { CreateFinoteDto } from '../dtos/create-finote.dto';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { FinoteCreatedEvent } from '@modules/accounting/domain/events/finote-created.event';
import { DRIZZLE } from '@database/drizzle.provider';

@Injectable()
export class FinoteService {
    constructor(
        @Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>,
        @Inject(ITransactionManager) private txManager: ITransactionManager,
        private sequenceService: SequenceGeneratorService,
        @Inject(IEventBus) private eventBus: IEventBus,
    ) { }

    async createFinote(dto: CreateFinoteDto, creatorId: number) {
        return this.txManager.runInTransaction(async () => {

            // 1. SINH MÃ TỰ ĐỘNG
            // Tự động chọn Prefix: INC (Income) hoặc EXP (Expense)
            const prefix = dto.type === 'INCOME' ? 'INC' : 'EXP';
            const finoteCode = await this.sequenceService.generateCode(prefix, {
                padLength: 4,
                resetYearly: true
            });

            // 2. CHUẨN BỊ DỮ LIỆU
            const newFinote = {
                code: finoteCode,
                type: dto.type,
                title: dto.title,
                amount: dto.amount.toString(), // Drizzle numeric yêu cầu string
                category: dto.category,
                description: dto.description,
                source_org_id: dto.organizationId || null,
                requested_by_id: creatorId,
                status: 'PENDING',
                deadline_at: new Date(dto.deadlineAt),
            };

            // 3. LƯU VÀO DATABASE
            const [savedFinote] = await this.db
                .insert(schema.finotes)
                .values(newFinote)
                .returning();

            // [TODO] Sau này có thể thêm EventBus ở đây: this.eventBus.publish(new FinoteCreatedEvent(...))
            // CHUẨN CLEAN ARCHITECTURE: Chỉ phát Event khi Transaction đã thành công 100%
            if (savedFinote) {
                this.eventBus.publish(
                    new FinoteCreatedEvent(savedFinote.id.toString(), {
                        finoteId: savedFinote.id,
                        code: savedFinote.code,
                        type: savedFinote.type,
                        title: savedFinote.title,
                        amount: savedFinote.amount,
                        creatorId: savedFinote.requested_by_id,
                        orgId: savedFinote.source_org_id,
                    })
                );
            }

            return savedFinote;
        });
    }
}
