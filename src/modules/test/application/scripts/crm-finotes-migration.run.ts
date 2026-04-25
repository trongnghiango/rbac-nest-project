import { NestFactory } from '@nestjs/core';
import { Module } from '@nestjs/common';
import { AppModule } from '../../../../bootstrap/app.module';
import { CrmLegacyMigrationService } from '../services/crm-legacy-migration.service';
import * as fs from 'fs';
import * as path from 'path';
import { parse } from 'csv-parse/sync';

@Module({
    imports: [AppModule],
    providers: [CrmLegacyMigrationService],
})
export class CrmFinotesMigrationModule {}

async function bootstrap() {
    console.log('🏁 Khởi động STAX CRM Legacy Migration Phase 4 (FINOTES)...');
    const app = await NestFactory.createApplicationContext(CrmFinotesMigrationModule);
    const mService = app.get(CrmLegacyMigrationService);

    try {
        const csvPath = path.join(process.cwd(), 'database', 'seeds', '04_.STAX.CRM.FN.2026.csv');
        const fileContent = fs.readFileSync(csvPath, 'utf-8');

        const records = parse(fileContent, {
            columns: false,
            skip_empty_lines: true,
            trim: true,
            relax_quotes: true,
            relax_column_count: true,
        });

        // Lọc bỏ header (dòng 1), tổng cộng (dòng 2), và các dòng rỗng/không có FN code (cột 3)
        const dataRecords = records.filter((r: any[]) => {
            const fnCode = r[3]?.trim();
            // Có FN code hợp lệ (bắt đầu bằng FN) và có số thứ tự hoặc company name
            return fnCode && fnCode.startsWith('FN');
        });

        console.log(`📂 Đọc được ${dataRecords.length} dòng dữ liệu FN hợp lệ.`);
        await mService.migrateFinotes(dataRecords);

    } catch (e) {
        console.error('❌ Lỗi toàn cục:', e);
    } finally {
        await app.close();
        process.exit(0);
    }
}

bootstrap();
