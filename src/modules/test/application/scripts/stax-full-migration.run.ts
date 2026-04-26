import { NestFactory } from '@nestjs/core';
import { Module } from '@nestjs/common';
import { AppModule } from '../../../../bootstrap/app.module';
import { StaxLegacyMigrationService } from '../services/stax-legacy-migration.service';
import * as fs from 'fs';
import * as path from 'path';
import { parse } from 'csv-parse/sync';
import * as schema from '@database/schema';
import { eq } from 'drizzle-orm';
import { DRIZZLE } from '@database/drizzle.provider';

@Module({
    imports: [AppModule],
    providers: [StaxLegacyMigrationService]
})
class MigrationModule {}

async function bootstrap() {
    const app = await NestFactory.createApplicationContext(MigrationModule);
    const migrationService = app.get(StaxLegacyMigrationService);
    const db = app.get(DRIZZLE);

    console.log('🏁 Starting STAX Universal Migration...');

    try {
        // 1. Lấy STAX Organization ID (Anchor)
        const staxOrg = await db.query.organizations.findFirst({
            where: eq(schema.organizations.isInternal, true)
        });

        if (!staxOrg) {
            throw new Error('❌ Không tìm thấy Master Organization (STAX). Vui lòng chạy Seeder trước.');
        }

        // 2. Đọc và Parse file CSV Nhân sự
        const csvPath = path.join(process.cwd(), 'database', 'seeds', 'THONG_TIN_NHAN_VIEN_TONG_HOP.csv');
        const fileContent = fs.readFileSync(csvPath, 'utf-8');

        const records = parse(fileContent, {
            columns: false,
            from_line: 4,
            skip_empty_lines: true,
            trim: true
        });

        // 3. Chuẩn hóa dữ liệu sang format script hiểu
        const mappedRecords = records.map((r: any) => ({
            maNv: r[1],
            ten: r[2],
            phongBan: r[3],
            chucVu: r[4],
            capBac: parseInt(r[0] || '1'),
            sdt: r[14],
            email: r[15],
            tinhTrang: r[6],
            start: r[7],
            ghiChu: r[27], // Tạm lấy cột xa xa
            raw: r
        })).filter((r: any) => r.maNv && r.ten);

        // 4. Khai hỏa di cư
        const result = await migrationService.migrateEmployees(mappedRecords, staxOrg.id);

        console.log('\n--- KẾT QUẢ DI CƯ NHÂN SỰ ---');
        console.log(`✅ Thành công: ${result.success}`);
        console.log(`🔄 Đã tồn tại: ${result.existing}`);
        console.log(`❌ Thất bại:   ${result.failed}`);
        console.log('-----------------------------\n');

        console.log('🎉 Migration Phase 1 complete!');

    } catch (error) {
        console.error('💥 Migration failed:', error);
    } finally {
        await app.close();
    }
}

bootstrap();
