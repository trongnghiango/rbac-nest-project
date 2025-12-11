import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  schema: './src/database/schema/*.schema.ts',
  out: './src/database/migrations',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL || `postgres://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`,
  },
  verbose: true,
  strict: true,
});
