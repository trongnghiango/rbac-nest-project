import { Module, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import databaseConfig from '@config/database.config';
import appConfig from '@config/app.config';
import loggingConfig from '@config/logging.config';
import redisConfig from '@config/redis.config'; // IMPORT CONFIG MỚI

import { CoreModule } from '@core/core.module';
import { SharedModule } from '@modules/shared/shared.module';
import { DrizzleModule } from '@database/drizzle.module';
import { LoggingModule } from '@modules/logging/logging.module';
import { RedisCacheModule } from '@core/shared/infrastructure/cache/redis-cache.module'; // IMPORT MODULE MỚI
import { RequestLoggingMiddleware } from '@api/middleware/request-logging.middleware';

import { UserModule } from '@modules/user/user.module';
import { AuthModule } from '@modules/auth/auth.module';
import { RbacModule } from '@modules/rbac/rbac.module';
import { TestModule } from '@modules/test/test.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      load: [databaseConfig, appConfig, loggingConfig, redisConfig],
    }),
    CoreModule,
    SharedModule,
    DrizzleModule,
    LoggingModule.forRootAsync(),
    RedisCacheModule, // ✅ Module Redis Global

    // Đã xóa CacheModule cũ

    UserModule,
    AuthModule,
    RbacModule,
    TestModule,
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(RequestLoggingMiddleware)
      .forRoutes({ path: '(.*)', method: RequestMethod.ALL });
  }
}
