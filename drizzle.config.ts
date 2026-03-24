import { defineConfig } from 'drizzle-kit';
import * as fs from 'fs';
import * as path from 'path';
import { config } from 'dotenv'; // 👈 1. Import dotenv

// 👇 2. Load biến môi trường NGAY LẬP TỨC
// Tự động chọn file .env phù hợp (.env.development hoặc .env mặc định)
// Nếu bạn chỉ dùng 1 file .env thì dòng này vẫn chạy tốt.
const envFile = process.env.NODE_ENV ? `.env.${process.env.NODE_ENV}` : '.env';
config({ path: envFile });

// 👇 LOGIC CỦA BẠN: Tìm file JS thật sự
let schemaPath = './src/database/schema/index.ts';
const prodSchemaPath = './dist/src/database/schema/index.js';

if (fs.existsSync(prodSchemaPath) && process.env.NODE_ENV === 'production') {
  console.log('✅ PRODUCTION MODE: Using Schema from dist/src/database/schema/index.js');
  // schemaPath = prodSchemaPath;
} else {
  console.log('⚠️ DEV MODE: Using Schema from src/database/schema/index.ts');
}

// Kiểm tra xem biến môi trường đã load chưa để debug
if (!process.env.DATABASE_URL && !process.env.DB_HOST) {
  throw new Error('❌ LỖI: Không tìm thấy biến môi trường! Hãy kiểm tra file .env');
}

export default defineConfig({
  schema: schemaPath,
  out: './database/migrations',
  dialect: 'postgresql',
  dbCredentials: {
    // Ưu tiên DATABASE_URL, nếu không có thì tự ghép chuỗi
    url: process.env.DATABASE_URL ||
      `postgres://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`,
  },
  verbose: true,
  strict: true,
});
