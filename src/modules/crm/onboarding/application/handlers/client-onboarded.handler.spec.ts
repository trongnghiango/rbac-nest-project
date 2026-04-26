import { Test, TestingModule } from '@nestjs/testing';
import { ClientOnboardedHandler } from './client-onboarded.handler';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { AUDIT_LOG_PORT } from '@core/shared/application/ports/audit-log.port';
import { ClientOnboardedEvent } from '../../domain/events/client-onboarded.event';

describe('ClientOnboardedHandler (Unit Test)', () => {
    let handler: ClientOnboardedHandler;
    let mockEventBus: any;
    let mockAuditLog: any;

    beforeEach(async () => {
        mockEventBus = {
            subscribe: jest.fn()
        };
        mockAuditLog = {
            log: jest.fn()
        };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                ClientOnboardedHandler,
                { provide: IEventBus, useValue: mockEventBus },
                { provide: AUDIT_LOG_PORT, useValue: mockAuditLog },
            ],
        }).compile();

        handler = module.get<ClientOnboardedHandler>(ClientOnboardedHandler);
    });

    it('should subscribe to CLIENT_ONBOARDED event on initialization', () => {
        handler.onModuleInit();
        expect(mockEventBus.subscribe).toHaveBeenCalledWith('CLIENT_ONBOARDED', expect.any(Function));
    });

    it('should trigger onboarding steps and log audit activities when event is handled', async () => {
        // 1. Phục hồi callback handler từ mock subscribe
        let eventHandler: Function;
        mockEventBus.subscribe.mockImplementation((name, cb) => {
            eventHandler = cb;
        });

        handler.onModuleInit();

        // 2. Giả lập một Event
        const testEvent = new ClientOnboardedEvent(
            '20',
            new Date(),
            { orgId: 20, contractId: 100, contractNumber: 'CONT-TEST' }
        );

        // 3. Thực thi callback (Giả lập event bus bắn tin)
        // @ts-ignore
        await eventHandler(testEvent);

        // 4. Kiểm chứng: Audit Log phải được gọi ít nhất 2 lần (Billing Init & Completed)
        expect(mockAuditLog.log).toHaveBeenCalledWith(expect.objectContaining({
            action: 'ONBOARDING.BILLING_INIT',
            organization_id: 20
        }));

        expect(mockAuditLog.log).toHaveBeenCalledWith(expect.objectContaining({
            action: 'ONBOARDING.COMPLETED',
            organization_id: 20
        }));
    });
});
