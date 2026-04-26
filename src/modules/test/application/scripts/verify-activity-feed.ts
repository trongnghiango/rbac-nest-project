import { NestFactory } from '@nestjs/core';
import { AppModule } from '../../../../bootstrap/app.module';
import { ACTIVITY_FEED_PORT, IActivityFeedService } from '@core/shared/application/ports/activity-feed.port';
import { INTERACTION_NOTE_PORT, IInteractionNoteService } from '@core/shared/application/ports/interaction-note.port';
import { AUDIT_LOG_PORT, IAuditLogService } from '@core/shared/application/ports/audit-log.port';

async function bootstrap() {
    const app = await NestFactory.createApplicationContext(AppModule);
    const activityFeedService = app.get<IActivityFeedService>(ACTIVITY_FEED_PORT);
    const noteService = app.get<IInteractionNoteService>(INTERACTION_NOTE_PORT);
    const auditLogService = app.get<IAuditLogService>(AUDIT_LOG_PORT);

    const ORG_ID = 20; // Dùng Org ID có sẵn từ migration

    console.log('--- 🛡️ VERIFY ACTIVITY FEED ENGINE ---');

    // 1. Tạo một Audit Log mẫu (Đã có organization_id)
    console.log('\n1. Ghi Audit Log mẫu...');
    await auditLogService.log({
        action: 'TEST.ACTIVITY_CHECK',
        resource: 'organizations',
        resource_id: ORG_ID.toString(),
        organization_id: ORG_ID,
        actor_name: 'Antigravity AI',
        metadata: { info: 'Kiểm tra tính năng timeline' }
    });

    // 2. Tạo một Interaction Note thủ công
    console.log('2. Thêm Interaction Note thủ công...');
    await noteService.create({
        organization_id: ORG_ID,
        type: 'CALL',
        content: 'Đã gọi điện cho khách hàng lúc 10h sáng. Khách đồng ý xem báo giá.',
        metadata: { duration: '5m' }
    });

    // 3. Truy vấn Timeline hội tụ
    console.log('3. Truy vấn Timeline hội tụ (Omnichannel)...');
    const timeline = await activityFeedService.getTimeline({ organizationId: ORG_ID });

    console.log(`\n✅ Kết quả: Tìm thấy ${timeline.items.length} hoạt động.`);
    
    timeline.items.forEach((item, index) => {
        const typeIcon = item.type === 'SYSTEM_AUDIT' ? '🤖' : '👤';
        console.log(`   [${index + 1}] ${typeIcon} [${item.timestamp.toISOString()}] ${item.actor.name}: ${item.displayText}`);
    });

    console.log('\n--- VERIFICATION COMPLETED ---');
    await app.close();
}

bootstrap();
