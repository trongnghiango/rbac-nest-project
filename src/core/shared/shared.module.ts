import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DrizzleModule } from '@database/drizzle.module';

// Import các file nội bộ trong cùng thư mục core/shared
import { DrizzleTransactionManager } from './infrastructure/persistence/drizzle-transaction.manager';
import { ITransactionManager } from './application/ports/transaction-manager.port';
import { EventBusModule } from './infrastructure/event-bus/event-bus.module';
import { CsvParserAdapter } from './infrastructure/adapters/csv-parser.adapter';
import { IFileParser } from './application/ports/file-parser.port';

@Global()
@Module({
    imports: [
        ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
        DrizzleModule,
        EventBusModule,
    ],
    providers: [
        {
            provide: ITransactionManager,
            useClass: DrizzleTransactionManager,
        },
        {
            provide: IFileParser,
            useClass: CsvParserAdapter,
        },
    ],
    exports: [ConfigModule, ITransactionManager, EventBusModule, IFileParser],
})
export class SharedModule { }
