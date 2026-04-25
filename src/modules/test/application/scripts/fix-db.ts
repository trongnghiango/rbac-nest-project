import { NestFactory } from '@nestjs/core';
import { AppModule } from '../../../../bootstrap/app.module';
import { sql } from 'drizzle-orm';
import { DRIZZLE } from '@database/drizzle.provider';

async function fix() {
    console.log('🔄 Bắt đầu vá DB...');
    const app = await NestFactory.createApplicationContext(AppModule);
    const db = app.get(DRIZZLE);
    await db.execute(sql`UPDATE leads SET source = 'ZALO' WHERE source = 'Zalo'`);
    console.log('✅ Đã sửa dữ liệu "Zalo" thành "ZALO" trong bảng leads');
    process.exit(0);
}
fix().catch(err => {
    console.error('❌ Lỗi:', err);
    process.exit(1);
});