import { Module } from '@nestjs/common';
import { FinoteService } from './application/services/finote.service';
import { SequenceGeneratorService } from '@core/shared/application/services/sequence-generator.service';
import { DrizzleSequenceRepository } from '@core/shared/infrastructure/persistence/drizzle-sequence.repository';
import { ISequenceRepository } from '@core/shared/domain/repositories/sequence.repository';

// Thêm các file vừa tạo
import { FinoteCreatedListener } from './application/listeners/finote-created.listener';
import { IDocumentGenerator } from './application/ports/document-generator.port';
import { DummyPdfGeneratorAdapter } from './infrastructure/adapters/dummy-pdf-generator.adapter';
import { IFileStorage } from './application/ports/file-storage.port';
import { LocalFileStorageAdapter } from './infrastructure/adapters/local-file-storage.adapter';
import { PuppeteerPdfGeneratorAdapter } from './infrastructure/adapters/puppeteer-pdf-generator.adapter';
import { IncomeTargetStrategy } from './application/strategies/target-resolver/income-target.strategy';
import { ExpenseTargetStrategy } from './application/strategies/target-resolver/expense-target.strategy';
import { TargetResolverFactory } from './application/strategies/target-resolver/target-resolver.factory';
import { FinoteController } from './infrastructure/controllers/finote.controller';
import { RbacModule } from '@modules/rbac/rbac.module';

@Module({
    imports: [RbacModule],
    controllers: [FinoteController],
    providers: [
        FinoteService,
        SequenceGeneratorService,
        { provide: ISequenceRepository, useClass: DrizzleSequenceRepository },

        // Đăng ký Listener
        FinoteCreatedListener,

        // Bắt cặp Interface (Port) với Implementation (Adapter)
        // { provide: IDocumentGenerator, useClass: DummyPdfGeneratorAdapter },
        { provide: IDocumentGenerator, useClass: PuppeteerPdfGeneratorAdapter },
        { provide: IFileStorage, useClass: LocalFileStorageAdapter },
        IncomeTargetStrategy,
        ExpenseTargetStrategy,
        TargetResolverFactory,
    ],
    exports: [FinoteService],
})
export class AccountingModule { }
