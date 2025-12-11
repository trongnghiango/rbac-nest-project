import { registerAs } from '@nestjs/config';

export default registerAs('database', () => {
  const isDev = process.env.NODE_ENV === 'development';

  return {
    type: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_NAME || 'rbac_system',

    // PRO TIP:
    // Trên Production nên tắt synchronize (false) và dùng migrationsRun (true)
    // Ở Dev có thể để synchronize true cho lẹ, nhưng dùng Migration an toàn hơn
    synchronize: isDev,
    logging: isDev ? ['error', 'warn', 'migration'] : ['error'],

    // --- MIGRATION CONFIG ---
    migrationsRun: true, // Tự động chạy migration khi start app
    migrations: [__dirname + '/../database/migrations/*{.ts,.js}'],
    // ------------------------

    autoLoadEntities: true,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  };
});
