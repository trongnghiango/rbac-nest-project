// src/modules/user/application/listeners/employee-account-requested.listener.ts
import { Injectable, Inject } from '@nestjs/common';
import { EventHandler } from '@core/shared/infrastructure/event-bus/decorators/event-handler.decorator';
import { EmployeeAccountRequestedEvent } from '@modules/employee/domain/events/employee-account-requested.event';
import { UserService } from '../services/user.service';
import { IEmployeeRepository } from '@modules/employee/domain/repositories/employee.repository';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { UserAccountCreatedEvent } from '@modules/user/domain/events/user-account-created.event';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';

@Injectable()
export class EmployeeAccountRequestedListener {
    constructor(
        private readonly userService: UserService,
        @Inject(IEventBus) private readonly eventBus: IEventBus,
    ) { }

    @EventHandler(EmployeeAccountRequestedEvent)
    async handle(event: EmployeeAccountRequestedEvent) {
        const { employeeId, username, email, fullName } = event.payload;

        const defaultPassword = 'Hrm@' + Math.floor(1000 + Math.random() * 9000);

        const newUser = await this.userService.createUser({
            id: undefined as any,
            username,
            password: defaultPassword,
            email,
            fullName,
        });

        // Bắn event thông báo User đã tạo xong, kèm theo "vết" là employeeId
        await this.eventBus.publish(
            new UserAccountCreatedEvent(String(newUser.id), {
                userId: newUser.id,
                username: newUser.username,
                metadata: { employeeId } // Truyền employeeId qua metadata
            })
        );
    }
}
