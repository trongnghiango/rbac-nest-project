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
