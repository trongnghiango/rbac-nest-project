import { NestFactory } from '@nestjs/core';
import { Module } from '@nestjs/common';
import { AppModule } from '../../../../bootstrap/app.module';
import { AUDIT_LOG_PORT, IAuditLogService } from '@core/shared/application/ports/audit-log.port';

@Module({
    imports: [AppModule],
})
export class VerifyAuditLogModule {}

async function bootstrap() {
    console.log('🏁 Bắt đầu kiểm chứng hệ thống Audit Log...');
    const app = await NestFactory.createApplicationContext(VerifyAuditLogModule);
    const auditService = app.get<IAuditLogService>(AUDIT_LOG_PORT);

    try {
        const testAction = `TEST_ACTION_${Date.now()}`;
        console.log(`-> Đang ghi log thử nghiệm: ${testAction}`);

        await auditService.log({
            action: testAction,
            resource: 'test_resource',
            resource_id: '999',
            actor_name: 'Antigravity Verification Bot',
            before: { status: 'OLD' },
            after: { status: 'NEW' },
            metadata: { note: 'Đây là log kiểm chứng hệ thống' }
        });

        console.log('-> Đang truy vấn lại log vừa ghi...');
        const result = await auditService.query({ action: testAction });

        if (result.data.length > 0 && result.data[0].action === testAction) {
            console.log('✅ THÀNH CÔNG: Log đã được ghi và truy vấn chính xác!');
            console.log('Chi tiết log:', JSON.stringify(result.data[0], null, 2));
        } else {
            console.error('❌ THẤT BẠI: Không tìm thấy log sau khi ghi.');
        }

    } catch (e) {
        console.error('❌ Lỗi kiểm chứng:', e);
    } finally {
        await app.close();
        process.exit(0);
    }
}

bootstrap();
