import { NestFactory } from '@nestjs/core';
import { AppModule } from '../../../../bootstrap/app.module';
import { LeadWorkflowService } from '../../../crm/application/services/lead-workflow.service';
import { LeadIntakeService } from '../../../crm/application/services/lead-intake.service';
import { ACTIVITY_FEED_PORT, IActivityFeedService } from '@core/shared/application/ports/activity-feed.port';

async function bootstrap() {
    console.log('--- 🤝 VERIFY UNIFIED ONBOARDING (NEW LEAD FLOW) ---');
    
    const app = await NestFactory.createApplicationContext(AppModule);
    const leadIntake = app.get(LeadIntakeService);
    const leadWorkflow = app.get(LeadWorkflowService);
    const activityFeed = app.get<IActivityFeedService>(ACTIVITY_FEED_PORT);

    const randomSuffix = Date.now();

    try {
        console.log(`\n1. Tạo Lead mới qua Intelligent Intake...`);
        const result = await leadIntake.intelligentIntake({
            fullName: 'Công ty Onboarding ' + randomSuffix,
            phone: '0988' + Math.floor(Math.random() * 1000000),
            email: `test-${randomSuffix}@onboarding.com`, // Lỗi unique email xử lý bằng random suffix
            serviceDemand: 'Hợp đồng Tư vấn STAX Onboarding',
            source: 'WEBSITE'
        });

        const leadId = result.leadId;
        const orgId = result.organizationId;
        console.log(`✅ Đã tạo Lead ID: ${leadId} cho Org ID: ${orgId}`);

        console.log(`\n2. Chốt Lead ID: ${leadId} (Gây ra event CLIENT_ONBOARDED)...`);
        await leadWorkflow.closeLeadAsWon({
            leadId: leadId,
            contractNumber: `CONT-AUTO-${randomSuffix}`,
            serviceType: 'ONBOARDING_PACKAGE',
            feeAmount: 35000000,
            actorId: 1,
            actorName: 'Nghĩa Automation'
        });

        console.log('3. Đợi 2 giây để handler xử lý bất đồng bộ...');
        await new Promise(resolve => setTimeout(resolve, 2000));

        console.log('4. Kiểm tra Timeline để xác nhận các bước Onboarding đã tự kích hoạt...');
        const timeline = await activityFeed.getTimeline({ organizationId: orgId });

        console.log(`\n✅ Kết quả Timeline cho Org ${orgId}:`);
        timeline.items.slice(0, 8).forEach((item, index) => {
            console.log(`   [${index + 1}] [${item.action}] ${item.displayText}`);
        });

        const onboardingLogs = timeline.items.filter(i => i.action?.startsWith('ONBOARDING.'));
        if (onboardingLogs.length >= 2) {
            console.log('\n🌟 THÀNH CÔNG RỰC RỠ: Quy trình Onboarding đã tự động thực thi chuỗi tác vụ!');
        } else {
            console.log('\n⚠️ Kiểm tra lại: Không tìm thấy đủ log Onboarding.');
        }

    } catch (error) {
        console.error('❌ Lỗi thực thi:', error.message);
    }

    await app.close();
}

bootstrap();
