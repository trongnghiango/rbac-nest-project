import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';

import databaseConfig from '../config/database.config';
import appConfig from '../config/app.config';
import loggingConfig from '../config/logging.config';

import { CoreModule } from '../core/core.module';
import { SharedModule } from '../modules/shared/shared.module';
import { UserModule } from '../modules/user/user.module';
import { AuthModule } from '../modules/auth/auth.module';
import { RbacModule } from '../modules/rbac/rbac.module';
import { TestModule } from '../modules/test/test.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      load: [databaseConfig, appConfig, loggingConfig],
    }),
    CoreModule,
    SharedModule,
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => {
        const dbConfig = config.get('database');
        return {
          ...dbConfig,
          // Load cả Entities và Migrations
          entities: [__dirname + '/../**/*.orm-entity{.ts,.js}'],
        };
      },
      inject: [ConfigService],
    }),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: () => ({ ttl: 300, max: 100 }),
      inject: [ConfigService],
    }),
    UserModule,
    AuthModule,
    RbacModule,
    TestModule,
  ],
})
export class AppModule {}
