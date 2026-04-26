import { Test, TestingModule } from '@nestjs/testing';
import { DrizzleAuditLogService } from './drizzle-audit-log.service';
import { DRIZZLE } from '@database/drizzle.provider';
import * as schema from '@database/schema';

describe('DrizzleAuditLogService', () => {
    let service: DrizzleAuditLogService;
    let mockDb: any;

    beforeEach(async () => {
        mockDb = {
            insert: jest.fn().mockReturnValue({
                values: jest.fn().mockResolvedValue(undefined),
            }),
            query: {
                auditLogs: {
                    findMany: jest.fn().mockResolvedValue([]),
                },
            },
            execute: jest.fn().mockResolvedValue({ rows: [{ count: 0 }] }),
        };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                DrizzleAuditLogService,
                {
                    provide: DRIZZLE,
                    useValue: mockDb,
                },
            ],
        }).compile();

        service = module.get<DrizzleAuditLogService>(DrizzleAuditLogService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('log', () => {
        it('should call db.insert with correct values', async () => {
            const entry = {
                action: 'TEST_ACTION',
                resource: 'test',
                resource_id: '1',
                actor_name: 'Test Actor',
            };

            await service.log(entry);

            expect(mockDb.insert).toHaveBeenCalledWith(schema.auditLogs);
            // values() is called on the object returned by insert()
            const insertResult = mockDb.insert(schema.auditLogs);
            expect(insertResult.values).toHaveBeenCalledWith(expect.objectContaining({
                action: 'TEST_ACTION',
                resource: 'test',
                actor_name: 'Test Actor',
            }));
        });

        it('should not throw error if db.insert fails (fire-and-forget)', async () => {
            mockDb.insert.mockImplementationOnce(() => {
                throw new Error('DB Error');
            });

            await expect(service.log({ action: 'FAIL' } as any)).resolves.not.toThrow();
        });
    });

    describe('logBatch', () => {
        it('should call db.insert with multiple values', async () => {
            const entries = [
                { action: 'A', resource: 'R', resource_id: '1' },
                { action: 'B', resource: 'R', resource_id: '2' },
            ];

            await service.logBatch(entries);

            const insertResult = mockDb.insert(schema.auditLogs);
            expect(insertResult.values).toHaveBeenCalledWith(expect.arrayContaining([
                expect.objectContaining({ action: 'A' }),
                expect.objectContaining({ action: 'B' }),
            ]));
        });
    });

    describe('query', () => {
        it('should call findMany with filters', async () => {
            const filter = {
                resource: 'leads',
                page: 1,
                limit: 10,
            };

            await service.query(filter);

            expect(mockDb.query.auditLogs.findMany).toHaveBeenCalledWith(expect.objectContaining({
                limit: 10,
                offset: 0,
            }));
        });
    });
});
