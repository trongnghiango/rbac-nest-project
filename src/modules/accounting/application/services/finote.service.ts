import { Injectable, Inject, NotFoundException, BadRequestException } from '@nestjs/common';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { SequenceGeneratorService } from '@core/shared/application/services/sequence-generator.service';
import { CreateFinoteDto } from '../dtos/create-finote.dto';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { FinoteCreatedEvent } from '@modules/accounting/domain/events/finote-created.event';
import { IFinoteRepository } from '../../domain/repositories/finote.repository';
import { Finote, FinoteType, FinoteStatus } from '../../domain/entities/finote.entity';
import { Money } from '@core/shared/domain/value-objects/money.vo';

@Injectable()
export class FinoteService {
    constructor(
        @Inject(IFinoteRepository) private readonly finoteRepo: IFinoteRepository,
        @Inject(ITransactionManager) private readonly txManager: ITransactionManager,
        @Inject(IEventBus) private readonly eventBus: IEventBus,
        private readonly sequenceService: SequenceGeneratorService,
    ) { }

    async approve(id: number, reviewerId: number) {
        const finote = await this.finoteRepo.findById(id);
        if (!finote) throw new NotFoundException('Không tìm thấy phiếu thu/chi');

        if (finote.status !== FinoteStatus.PENDING) {
          throw new BadRequestException('Chỉ có thể duyệt phiếu đang ở trạng thái PENDING');
        }

        finote.status = FinoteStatus.APPROVED;
        finote.reviewerId = reviewerId;
        finote.updatedAt = new Date();

        return this.finoteRepo.save(finote);
    }

    async reject(id: number, reviewerId: number, reason: string) {
        const finote = await this.finoteRepo.findById(id);
        if (!finote) throw new NotFoundException('Không tìm thấy phiếu thu/chi');

        if (finote.status !== FinoteStatus.PENDING) {
          throw new BadRequestException('Chỉ có thể từ chối phiếu đang ở trạng thái PENDING');
        }

        finote.status = FinoteStatus.REJECTED;
        finote.reviewerId = reviewerId;
        finote.description = `${finote.description || ''} [Lý do từ chối: ${reason}]`.trim();
        finote.updatedAt = new Date();

        return this.finoteRepo.save(finote);
    }

    async createFinote(dto: CreateFinoteDto, creatorId: number) {
        return this.txManager.runInTransaction(async () => {
            const prefix = dto.type === FinoteType.INCOME ? 'INC' : 'EXP';
            const finoteCode = await this.sequenceService.generateCode(prefix, { padLength: 4, resetYearly: true });

            // Khởi tạo Entity bằng VO Money, không tạo Raw DB Object nữa!
            const newFinote = new Finote({
                code: finoteCode,
                type: dto.type as FinoteType,
                title: dto.title,
                totalAmount: new Money(dto.amount), // <-- Sử dụng VO Money
                // currency: dto,
                currency: 'VND',
                category: dto.category,
                description: dto.description,
                sourceOrgId: dto.organizationId,
                requestedById: creatorId,
                status: FinoteStatus.PENDING,
                deadlineAt: new Date(dto.deadlineAt),
            });

            const savedFinote = await this.finoteRepo.save(newFinote);

            this.eventBus.publish(
                new FinoteCreatedEvent(savedFinote.id!.toString(), {
                    finoteId: savedFinote.id!,
                    code: savedFinote.code,
                    type: savedFinote.type,
                    title: savedFinote.title,
                    amount: savedFinote.totalAmount.getAmount().toString(),
                    creatorId: savedFinote.requestedById,
                    orgId: savedFinote.sourceOrgId,
                })
            );

            return savedFinote;
        });
    }
}
