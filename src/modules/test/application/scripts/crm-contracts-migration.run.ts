import { NestFactory } from '@nestjs/core';
import { Module } from '@nestjs/common';
import { AppModule } from '../../../../bootstrap/app.module';
import { CrmLegacyMigrationService } from '../services/crm-legacy-migration.service';

@Module({
    imports: [AppModule],
    providers: [CrmLegacyMigrationService],
})
export class CrmContractsMigrationModule {}

async function bootstrap() {
    console.log('🏁 Khởi động STAX CRM Legacy Migration Phase 3 (CONTRACTS SYNTHESIZER)...');
    const app = await NestFactory.createApplicationContext(CrmContractsMigrationModule);
    const mService = app.get(CrmLegacyMigrationService);

    try {
        await mService.synthesizeContracts();
    } catch (e) {
        console.error('❌ Lỗi toàn cục:', e);
    } finally {
        await app.close();
        process.exit(0);
    }
}

bootstrap();
