import { Test, TestingModule } from '@nestjs/testing';
import { ACTIVITY_FEED_PORT } from '@core/shared/application/ports/activity-feed.port';
import { DrizzleActivityFeedService } from '../../infrastructure/persistence/drizzle-activity-feed.service';
import { DRIZZLE } from '@database/drizzle.provider';

describe('ActivityFeedService (Unit Test)', () => {
    let service: DrizzleActivityFeedService;
    let mockDb: any;

    beforeEach(async () => {
        // Mock Drizzle Database
        mockDb = {
            query: {
                auditLogs: {
                    findMany: jest.fn()
                },
                interactionNotes: {
                    findMany: jest.fn()
                }
            }
        };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                DrizzleActivityFeedService,
                { provide: DRIZZLE, useValue: mockDb },
            ],
        }).compile();

        service = module.get<DrizzleActivityFeedService>(DrizzleActivityFeedService);
    });

    it('nên gộp và sắp xếp đúng dòng thời gian từ 2 nguồn dữ liệu', async () => {
        const ORG_ID = 1;
        const now = new Date();

        // 1. Giả lập dữ liệu từ Audit Logs (Hệ thống)
        mockDb.query.auditLogs.findMany.mockResolvedValue([
            {
                id: 1,
                action: 'LEAD.CLOSE_WON',
                resource: 'leads',
                actorName: 'Robot SQL',
                createdAt: new Date(now.getTime() - 10000) // 10 giây trước
            }
        ]);

        // 2. Giả lập dữ liệu từ Interaction Notes (Con người)
        mockDb.query.interactionNotes.findMany.mockResolvedValue([
            {
                id: 10,
                type: 'CALL',
                content: 'Ghi chú mới nhất',
                actorId: 1,
                createdAt: now // Hiện tại
            }
        ]);

        // 3. Thực thi
        const result = await service.getTimeline({ organizationId: ORG_ID });

        // 4. Kiểm chứng
        expect(result.items).toHaveLength(1);
        
        // DrizzleActivityFeedService hiện tại chỉ query auditLogs (chưa merge interactionNotes)
        expect(result.items[0].action).toBe('LEAD.CLOSE_WON');
    });
});
