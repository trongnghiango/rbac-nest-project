import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { Pool } from 'pg';
import * as dotenv from 'dotenv';
import * as path from 'path';

// Nạp env nếu chạy rời
dotenv.config({ path: path.resolve(process.cwd(), '.env.production') });

const runMigration = async () => {
    console.log('⏳ Running production migrations...');

    const pool = new Pool({
        host: process.env.DB_HOST,
        port: Number(process.env.DB_PORT || 5432),
        user: process.env.DB_USERNAME,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
    });

    const db = drizzle(pool);

    // Cần đảm bảo bạn đã generate folder 'drizzle' chứa các file SQL trước khi build image
    // Bằng lệnh: npx drizzle-kit generate
    await migrate(db, { migrationsFolder: './drizzle' });

    console.log('✅ Migrations applied successfully!');
    await pool.end();
};

runMigration().catch((err) => {
    console.error('❌ Migration failed:', err);
    process.exit(1);
});
