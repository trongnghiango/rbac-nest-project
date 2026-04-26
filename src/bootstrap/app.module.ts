import { Module, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ServeStaticModule } from '@nestjs/serve-static';
import * as path from 'path';

import databaseConfig from '@config/database.config';
import appConfig from '@config/app.config';
import loggingConfig from '@config/logging.config';
import redisConfig from '@config/redis.config';
import eventBusConfig from '@config/event-bus.config';
import dentalConfig from '@config/dental.config';
import authConfig from '@config/auth.config';

import { CoreModule } from '@core/core.module';
import { SharedModule } from '@core/shared/shared.module';
import { DrizzleModule } from '@database/drizzle.module';
import { LoggingModule } from '@modules/logging/logging.module';
import { RedisCacheModule } from '@core/shared/infrastructure/cache/redis-cache.module';
import { RequestLoggingMiddleware } from '@api/middleware/request-logging.middleware';
import { ActivityFeedController } from '@modules/logging/infrastructure/controllers/activity-feed.controller';
import { InteractionNoteController } from '@modules/logging/infrastructure/controllers/interaction-note.controller';

import { UserModule } from '@modules/user/user.module';
import { AuthModule } from '@modules/auth/auth.module';
import { RbacModule } from '@modules/rbac/rbac.module';
import { TestModule } from '@modules/test/test.module';
import { NotificationModule } from '@modules/notification/notification.module';
import { ChatbotCoreModule } from '@modules/chatbot-core/chatbot-core.module';
import { OrgStructureModule } from '@modules/org-structure/org-structure.module';
import { EmployeeModule } from '@modules/employee/employee.module';
import { AccountingModule } from '@modules/accounting/accounting.module';
import { CrmModule } from '@modules/crm/crm.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: `.env.${process.env.NODE_ENV || 'development'}`,
      load: [
        databaseConfig,
        appConfig,
        loggingConfig,
        authConfig,
        redisConfig,
        eventBusConfig,
        dentalConfig,
      ],
    }),

    ServeStaticModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => {
        // path.resolve(config.get('dental.outputDir') || 'uploads/dental/converted',)
        const outputDir = config.get<string>('dental.outputDir');
        return [
          {
            rootPath: outputDir,
            serveRoot: '/models',
            // 👇 SỬA DÒNG NÀY:
            // CŨ (Lỗi): exclude: ['/api/(.*)'],
            // MỚI (Đúng): Dùng cú pháp của NestJS mới hoặc đặt tên cho tham số wildcard
            exclude: ['/api/{*path}'],
            serveStaticOptions: {
              setHeaders: (res) => {
                res.setHeader('Access-Control-Allow-Origin', '*');
                res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
              },
            },
          },
        ]
      },
      inject: [ConfigService],
    }),

    CoreModule,
    SharedModule,
    DrizzleModule,
    LoggingModule,
    RedisCacheModule,
    ChatbotCoreModule,

    UserModule,
    AuthModule,
    RbacModule,
    NotificationModule,

    TestModule,

    //
    OrgStructureModule,
    EmployeeModule,
    AccountingModule,
    CrmModule,
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(RequestLoggingMiddleware)
      .forRoutes({ path: '{*path}', method: RequestMethod.ALL });
  }
}
