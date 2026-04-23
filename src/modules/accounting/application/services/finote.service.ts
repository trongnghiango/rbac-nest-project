// src/modules/accounting/application/services/finote.service.ts
import { Injectable, Inject } from '@nestjs/common';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { SequenceGeneratorService } from '@core/shared/application/services/sequence-generator.service';
import { CreateFinoteDto } from '../dtos/create-finote.dto';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { FinoteCreatedEvent } from '@modules/accounting/domain/events/finote-created.event';
import { IFinoteRepository } from '../../domain/repositories/finote.repository';

@Injectable()
export class FinoteService {
    constructor(
        @Inject(IFinoteRepository) private readonly finoteRepo: IFinoteRepository,
        @Inject(ITransactionManager) private readonly txManager: ITransactionManager,
        @Inject(IEventBus) private readonly eventBus: IEventBus,
        private readonly sequenceService: SequenceGeneratorService,
    ) { }

    async createFinote(dto: CreateFinoteDto, creatorId: number) {
        return this.txManager.runInTransaction(async () => {
            const prefix = dto.type === 'INCOME' ? 'INC' : 'EXP';
            const finoteCode = await this.sequenceService.generateCode(prefix, {
                padLength: 4,
                resetYearly: true
            });

            const newFinoteData = {
                code: finoteCode,
                type: dto.type,
                title: dto.title,
                amount: dto.amount.toString(),
                category: dto.category,
                description: dto.description,
                source_org_id: dto.organizationId || null,
                requested_by_id: creatorId,
                status: 'PENDING',
                deadline_at: new Date(dto.deadlineAt),
            };

            const savedFinote = await this.finoteRepo.save(newFinoteData);

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
