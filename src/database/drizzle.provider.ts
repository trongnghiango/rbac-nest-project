import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { ConfigService } from '@nestjs/config';
import * as schema from './schema';

export const DRIZZLE = 'DRIZZLE_CONNECTION';

export const drizzleProvider = {
  provide: DRIZZLE,
  inject: [ConfigService],
  useFactory: async (configService: ConfigService) => {
    const connectionString = configService.get<string>('database.url');

    const host = configService.get<string>('database.host');
    const port = configService.get<number>('database.port');
    const user = configService.get<string>('database.username');
    const password = configService.get<string>('database.password');
    const database = configService.get<string>('database.database');

    const poolConfig = connectionString
      ? { connectionString }
      : { host, port, user, password, database };

    const pool = new Pool(poolConfig);
    return drizzle(pool, { schema });
  },
};
