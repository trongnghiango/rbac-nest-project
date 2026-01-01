import { defineConfig } from 'drizzle-kit';
import * as fs from 'fs';
import * as path from 'path';

// 👇 LOGIC QUAN TRỌNG: Tìm file JS thật sự
let schemaPath = './src/database/schema/index.ts';

// Đường dẫn file JS sau khi build (Dựa trên kết quả lệnh find bạn chạy lúc nãy)
const prodSchemaPath = './dist/src/database/schema/index.js';

if (fs.existsSync(prodSchemaPath)) {
  console.log(
    '✅ PRODUCTION MODE: Using Schema from dist/src/database/schema/index.js',
  );
  schemaPath = prodSchemaPath;
} else {
  console.log('⚠️ DEV MODE: Using Schema from src/database/schema/index.ts');
}

export default defineConfig({
  // Trỏ thẳng vào index.ts - nơi export tất cả schema
  // schema: './src/database/schema/index.ts',
  schema: schemaPath,
  out: './src/database/migrations',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL || `postgres://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`,
  },
  verbose: true,
  strict: true,
});
