// src/modules/accounting/application/services/finote.service.ts
import { Injectable, Inject } from '@nestjs/common';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { SequenceGeneratorService } from '@core/shared/application/services/sequence-generator.service';
import { CreateFinoteDto } from '../dtos/create-finote.dto';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { FinoteCreatedEvent } from '@modules/accounting/domain/events/finote-created.event';
import { IFinoteRepository } from '../../domain/repositories/finote.repository';
import { Finote } from '../../domain/entities/finote.entity';
import { Money } from '@core/shared/domain/value-objects/money.vo';

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
            const finoteCode = await this.sequenceService.generateCode(prefix, { padLength: 4, resetYearly: true });

            // Khởi tạo Entity bằng VO Money, không tạo Raw DB Object nữa!
            const newFinote = new Finote({
                code: finoteCode,
                type: dto.type,
                title: dto.title,
                amount: new Money(dto.amount), // <-- Sử dụng VO Money
                // currency: dto,
                currency: 'VND',
                category: dto.category,
                description: dto.description,
                sourceOrgId: dto.organizationId,
                requestedById: creatorId,
                status: 'PENDING',
                deadlineAt: new Date(dto.deadlineAt),
            });

            const savedFinote = await this.finoteRepo.save(newFinote);

            this.eventBus.publish(
                new FinoteCreatedEvent(savedFinote.id!.toString(), {
                    finoteId: savedFinote.id!,
                    code: savedFinote.code,
                    type: savedFinote.type,
                    title: savedFinote.title,
                    amount: savedFinote.amount.getAmount().toString(),
                    creatorId: savedFinote.requestedById,
                    orgId: savedFinote.sourceOrgId,
                })
            );

            return savedFinote;
        });
    }
}
