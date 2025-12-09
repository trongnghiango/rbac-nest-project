#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

ensure_dir() {
    for dir in "$@"; do
        mkdir -p "$dir"
    done
}

log "🚀 REFACTORING PROJECT STRUCTURE..."

# 1. CREATE DIRECTORIES FOR CORE & CONFIG
ensure_dir src/core/{interceptors,filters}
ensure_dir src/config

# ============================================
# 2. CREATE CORE MODULE (INTERCEPTORS, FILTERS)
# ============================================
log "Creating Core Module..."

# Transform Interceptor
cat > src/core/interceptors/transform-response.interceptor.ts << 'EOF'
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

@Injectable()
export class TransformResponseInterceptor<T> implements NestInterceptor<T, any> {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => ({
        success: true,
        statusCode: context.switchToHttp().getResponse().statusCode,
        message: this.reflector.get<string>('response_message', context.getHandler()) || 'Success',
        result: data,
      })),
    );
  }
}
EOF

# Exception Filter
cat > src/core/filters/http-exception.filter.ts << 'EOF'
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status = exception.getStatus
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionResponse: any = exception.getResponse();
    const errorMsg = exceptionResponse.message;

    const responseBody = {
      success: false,
      statusCode: status,
      message: typeof exceptionResponse === 'string' ? exceptionResponse : 'Error',
      errors: errorMsg || null,
      path: request.url,
      timestamp: new Date().toISOString(),
    };

    if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
      responseBody.message = exceptionResponse['error'] || exceptionResponse['message'];
      responseBody.errors = exceptionResponse['message'];
    }

    response.status(status).json(responseBody);
  }
}
EOF

# Core Module Definition
cat > src/core/core.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';

import { TransformResponseInterceptor } from './interceptors/transform-response.interceptor';
import { HttpExceptionFilter } from './filters/http-exception.filter';

@Module({
  providers: [
    {
      provide: APP_PIPE,
      useValue: new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformResponseInterceptor,
    },
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
})
export class CoreModule {}
EOF

# ============================================
# 3. CREATE CONFIGURATION FILES
# ============================================
log "Creating Config Files..."

cat > src/config/app.config.ts << 'EOF'
import { registerAs } from '@nestjs/config';

export default registerAs('app', () => ({
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '3000', 10),
  apiPrefix: 'api',
}));
EOF

cat > src/config/database.config.ts << 'EOF'
import { registerAs } from '@nestjs/config';

export default registerAs('database', () => ({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_NAME || 'rbac_system',
  synchronize: process.env.NODE_ENV === 'development',
  logging: process.env.NODE_ENV === 'development',
}));
EOF

cat > src/config/logging.config.ts << 'EOF'
import { registerAs } from '@nestjs/config';

export default registerAs('logging', () => ({
  level: process.env.LOG_LEVEL || 'info',
}));
EOF

# ============================================
# 4. UPDATE APP MODULE
# ============================================
log "Updating AppModule to use Core & Config..."

cat > src/bootstrap/app.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';

// Configs
import databaseConfig from '../config/database.config';
import appConfig from '../config/app.config';
import loggingConfig from '../config/logging.config';

// Core & Shared
import { CoreModule } from '../core/core.module';
import { SharedModule } from '../modules/shared/shared.module';

// Feature Modules
import { UserModule } from '../modules/user/user.module';
import { AuthModule } from '../modules/auth/auth.module';
import { RbacModule } from '../modules/rbac/rbac.module';
import { TestModule } from '../modules/test/test.module';

@Module({
  imports: [
    // 1. Config
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      load: [databaseConfig, appConfig, loggingConfig],
    }),

    // 2. Core (Global Pipes/Filters/Interceptors)
    CoreModule,
    SharedModule,

    // 3. Database
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        ...config.get('database'),
        entities: [__dirname + '/../**/*.entity{.ts,.js}'],
        autoLoadEntities: true,
      }),
      inject: [ConfigService],
    }),

    // 4. Cache
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: () => ({ ttl: 300, max: 100 }),
      inject: [ConfigService],
    }),

    // 5. Features
    UserModule,
    AuthModule,
    RbacModule,
    TestModule, // Uncommented TestModule for testing
  ],
})
export class AppModule {}
EOF

# ============================================
# 5. UPDATE MAIN.TS
# ============================================
log "Updating Main.ts..."

cat > src/bootstrap/main.ts << 'EOF'
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService);

  // Note: Global Pipes, Filters, Interceptors are loaded via CoreModule

  const prefix = config.get('app.apiPrefix', 'api');
  app.setGlobalPrefix(prefix);
  app.enableCors();

  const port = config.get('app.port', 3000);
  await app.listen(port);

  console.log(`🚀 Application is running on: http://localhost:${port}/${prefix}`);
  console.log(`📊 Health check: http://localhost:${port}/${prefix}/test/health`);
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
bootstrap().catch((err) => console.error('Err::', err['message']));
EOF

success "✅ PROJECT REFACTORED SUCCESSFULLY!"
echo "Run 'docker-compose up -d --build' to apply changes."
