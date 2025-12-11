import { Module, Global } from '@nestjs/common';
import { drizzleProvider } from './drizzle.provider';
import { ConfigModule } from '@nestjs/config';

@Global()
@Module({
  imports: [ConfigModule],
  providers: [drizzleProvider],
  exports: [drizzleProvider],
})
export class DrizzleModule {}
