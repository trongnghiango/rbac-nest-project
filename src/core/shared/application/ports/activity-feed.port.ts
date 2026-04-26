export const ACTIVITY_FEED_PORT = Symbol('ACTIVITY_FEED_PORT');

export interface ActivityFeedItem {
    id: number;
    action: string;
    resource: string;
    resourceId?: string;
    organizationId?: number;
    actorId: string | number;
    actorName: string;
    content?: string;
    metadata?: Record<string, any>;
    severity: string;
    createdAt: Date;
}

export interface GetTimelineQuery {
    organizationId: number;
    page?: number;
    limit?: number;
}

export interface ActivityFeedResponse {
    items: ActivityFeedItem[];
    total?: number;
}

export interface IActivityFeedService {
    getTimeline(query: GetTimelineQuery): Promise<ActivityFeedResponse>;
}
