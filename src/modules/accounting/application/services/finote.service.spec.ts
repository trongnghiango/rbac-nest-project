import { Test, TestingModule } from '@nestjs/testing';
import { FinoteService } from './finote.service';
import { IFinoteRepository } from '../../domain/repositories/finote.repository';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { SequenceGeneratorService } from '@core/shared/application/services/sequence-generator.service';

describe('FinoteService', () => {
    let service: FinoteService;

    const mockFinoteRepo = {
        save: jest.fn(),
    };
    const mockTransactionManager = {
        runInTransaction: jest.fn((cb) => cb()),
    };
    const mockEventBus = {
        publish: jest.fn(),
    };
    const mockSequenceService = {
        generateCode: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                FinoteService,
                { provide: IFinoteRepository, useValue: mockFinoteRepo },
                { provide: ITransactionManager, useValue: mockTransactionManager },
                { provide: IEventBus, useValue: mockEventBus },
                { provide: SequenceGeneratorService, useValue: mockSequenceService },
            ],
        }).compile();

        service = module.get<FinoteService>(FinoteService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    it('should create finote and publish event successfully (scaffold)', async () => {
        // TODO: Implement actual test
    });
});
