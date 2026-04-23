// src/modules/employee/application/listeners/user-account-created.listener.ts

import { ILogger, LOGGER_TOKEN } from "@core/shared/application/ports/logger.port";
import { EventHandler } from "@core/shared/infrastructure/event-bus/decorators/event-handler.decorator";
import { IEmployeeRepository } from "@modules/employee/domain/repositories/employee.repository";
import { UserAccountCreatedEvent } from "@modules/user/domain/events/user-account-created.event";
import { Inject, Injectable } from "@nestjs/common";

@Injectable()
export class UserAccountCreatedListener {
    constructor(
        @Inject(IEmployeeRepository) private readonly employeeRepo: IEmployeeRepository,
        @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    ) { }

    @EventHandler(UserAccountCreatedEvent)
    async handle(event: UserAccountCreatedEvent) {
        const { userId, metadata } = event.payload;
        const employeeId = metadata?.employeeId;

        if (!employeeId) return;

        await this.employeeRepo.save({
            id: employeeId,
            userId: userId,
        });

        this.logger.info(`Đã liên kết thành công UserId ${userId} cho EmployeeId ${employeeId}`);
    }
}
