import { InteractionNoteRecord } from './interaction-note.port';

export const ACTIVITY_FEED_PORT = Symbol('ACTIVITY_FEED_PORT');

export interface ActivityItem {
    id: string | number;
    timestamp: Date;
    type: 'SYSTEM_AUDIT' | 'HUMAN_NOTE';
    actor: {
        id: number | null;
        name: string;
    };
    action: string;
    displayText: string;
    severity: 'INFO' | 'WARN' | 'ERROR';
    metadata?: any;
    reference?: {
        type: string;
        id: string | number;
    };
}

export interface ActivityFeedQuery {
    organizationId: number;
    page?: number;
    limit?: number;
    type?: 'SYSTEM_AUDIT' | 'HUMAN_NOTE';
}

export interface IActivityFeedService {
    getTimeline(query: ActivityFeedQuery): Promise<{
        items: ActivityItem[];
        total: number;
    }>;
}
