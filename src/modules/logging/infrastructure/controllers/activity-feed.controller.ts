import { Controller, Get, Param, Query, Inject, ParseIntPipe } from '@nestjs/common';
import { ACTIVITY_FEED_PORT, IActivityFeedService } from '@core/shared/application/ports/activity-feed.port';
import { ApiTags, ApiOperation, ApiQuery } from '@nestjs/swagger';

export interface TimelineQuery {
    page?: number;
    limit?: number;
    type?: 'SYSTEM_AUDIT' | 'HUMAN_NOTE';
}

@ApiTags('Logging & Activities')
@Controller('organizations/:orgId/timeline')
export class ActivityFeedController {
    constructor(
        @Inject(ACTIVITY_FEED_PORT) private readonly activityFeedService: IActivityFeedService
    ) {}

    @Get()
    @ApiOperation({ summary: 'Lấy dòng thời gian hoạt động của doanh nghiệp' })
    @ApiQuery({ name: 'page', required: false })
    @ApiQuery({ name: 'limit', required: false })
    async getTimeline(
        @Param('orgId', ParseIntPipe) orgId: number,
        @Query('page') page?: string,
        @Query('limit') limit?: string,
    ) {
        return this.activityFeedService.getTimeline({
            organizationId: orgId,
            page: page ? parseInt(page) : 1,
            limit: limit ? parseInt(limit) : 20,
        });
    }
}
