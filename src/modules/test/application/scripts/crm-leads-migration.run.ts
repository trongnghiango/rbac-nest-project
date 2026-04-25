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
export class CrmLeadsMigrationModule {}

async function bootstrap() {
    console.log('🏁 Khởi động STAX CRM Legacy Migration Phase 2 (LEADS)...');
    const app = await NestFactory.createApplicationContext(CrmLeadsMigrationModule);
    const mService = app.get(CrmLegacyMigrationService);

    try {
        const csvPath = path.join(process.cwd(), 'database', 'seeds', '2026.STAX.CRM.Lead.csv');
        const fileContent = fs.readFileSync(csvPath, 'utf-8');

        // Parse thô, bỏ qua header phức tạp
        const records = parse(fileContent, {
            columns: false,
            skip_empty_lines: true,
            trim: true,
            relax_quotes: true
        });

        // Lọc bỏ header dựa trên value STT và dọn dẹp các dòng rác
        const dataRecords = records.filter(r => r[0] && r[0] !== 'STT.');

        await mService.migrateLeads(dataRecords);

    } catch (e) {
        console.error('❌ Lỗi toàn cục:', e);
    } finally {
        await app.close();
        process.exit(0);
    }
}

bootstrap();
