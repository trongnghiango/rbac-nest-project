import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { WinstonFactory } from './infrastructure/winston/winston.factory';
import { WinstonLoggerAdapter } from './infrastructure/winston/winston-logger.adapter';
import { DrizzleAuditLogService } from './infrastructure/persistence/drizzle-audit-log.service';
import { DrizzleInteractionNoteService } from './infrastructure/persistence/drizzle-interaction-note.service';
import { DrizzleActivityFeedService } from './infrastructure/persistence/drizzle-activity-feed.service';
import { ActivityFeedController } from './infrastructure/controllers/activity-feed.controller';
import { InteractionNoteController } from './infrastructure/controllers/interaction-note.controller';
import { AuditDomainEventHandler } from './application/handlers/audit-domain-event.handler';

// Import Token
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { AUDIT_LOG_PORT } from '@core/shared/application/ports/audit-log.port';
import { INTERACTION_NOTE_PORT } from '@core/shared/application/ports/interaction-note.port';
import { ACTIVITY_FEED_PORT } from '@core/shared/application/ports/activity-feed.port';

@Global()
@Module({
  imports: [ConfigModule],
  controllers: [
    ActivityFeedController,
    InteractionNoteController,
  ],
  providers: [
    WinstonFactory,
    {
      provide: 'WINSTON_LOGGER',
      useFactory: (factory: WinstonFactory) => factory.createLogger(),
      inject: [WinstonFactory],
    },
    {
      provide: LOGGER_TOKEN,
      useClass: WinstonLoggerAdapter,
    },
    {
      provide: AUDIT_LOG_PORT,
      useClass: DrizzleAuditLogService,
    },
    {
      provide: INTERACTION_NOTE_PORT,
      useClass: DrizzleInteractionNoteService,
    },
    {
      provide: ACTIVITY_FEED_PORT,
      useClass: DrizzleActivityFeedService,
    },
    AuditDomainEventHandler,
  ],
  exports: [
    LOGGER_TOKEN, 
    AUDIT_LOG_PORT, 
    INTERACTION_NOTE_PORT, 
    ACTIVITY_FEED_PORT
  ],
})
export class LoggingModule {
  constructor() {
    console.log('✅ LoggingModule initialized');
  }
}
