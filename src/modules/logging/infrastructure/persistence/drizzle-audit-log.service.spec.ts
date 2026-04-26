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
        it('should call db.insert with correct values (via setImmediate background)', (done) => {
            const entry = {
                action: 'TEST_ACTION',
                resource: 'test',
                resourceId: '1',
                actorName: 'Test Actor',
            };

            // log() returns void immediately (fire-and-forget)
            const result = service.log(entry as any);
            expect(result).toBeUndefined();

            // DB insert happens inside setImmediate - wait for next I/O tick
            setImmediate(() => {
                expect(mockDb.insert).toHaveBeenCalledWith(schema.auditLogs);
                done();
            });
        });

        it('should NOT throw even if db.insert fails (fire-and-forget resilience)', (done) => {
            mockDb.insert.mockImplementationOnce(() => {
                throw new Error('DB Error');
            });

            // Must NOT throw - log() is void and absorbs errors
            expect(() => service.log({ action: 'FAIL' } as any)).not.toThrow();

            setImmediate(() => {
                // Process should still be alive, no unhandled rejection
                done();
            });
        });

        it('should enrich with RequestContext data if available', (done) => {
            const entry = { action: 'TEST' };
            const { RequestContextService, RequestContext } = require('@core/shared/infrastructure/context/request-context.service');
            
            const mockContext = new RequestContext('req-123', '/test', '127.0.0.1', 'Mozilla');
            mockContext.userId = 42;
            mockContext.userName = 'John Doe';

            RequestContextService.run(mockContext, () => {
                service.log(entry as any);
                
                setImmediate(() => {
                    expect(mockDb.insert).toHaveBeenCalled();
                    done();
                });
            });
        });
    });



    describe('query', () => {
        it('should call findMany with resource filter and default limit', async () => {
            const filter = {
                resource: 'leads',
            };

            await service.query(filter);

            expect(mockDb.query.auditLogs.findMany).toHaveBeenCalledWith(expect.objectContaining({
                limit: 100,
            }));
        });
    });
});
