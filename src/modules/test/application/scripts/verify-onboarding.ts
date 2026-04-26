import { Injectable, Logger } from '@nestjs/common';
import { IActivityFeedService } from '@core/shared/application/ports/activity-feed.port';
import { Inject } from '@nestjs/common';
import { ACTIVITY_FEED_PORT } from '@core/shared/application/ports/activity-feed.port';

@Injectable()
export class VerifyOnboardingScript {
    private readonly logger = new Logger(VerifyOnboardingScript.name);

    constructor(
        @Inject(ACTIVITY_FEED_PORT) private readonly activityFeedService: IActivityFeedService
    ) {}

    async run(orgId: number) {
        this.logger.log(`🔍 Bắt đầu kiểm chứng luồng Onboarding & Timeline cho Org: ${orgId}`);

        const result = await this.activityFeedService.getTimeline({ organizationId: orgId });
        const items = result.items;

        console.log(`\n--- TIMELINE HOẠT ĐỘNG (Total: ${items.length}) ---`);
        items.slice(0, 8).forEach((item, index) => {
            console.log(`   [${index + 1}] [${item.action}] ${item.action}`);
        });

        const onboardingLogs = items.filter(i => i.action?.startsWith('ONBOARDING.') || i.action?.includes('WON'));
        
        if (onboardingLogs.length > 0) {
            console.log(`\n✅ Thành công: Tìm thấy ${onboardingLogs.length} logs liên quan đến onboarding.`);
            return true;
        } else {
            console.log('\n❌ Thất bại: Không tìm thấy log onboarding nào.');
            return false;
        }
    }
}
