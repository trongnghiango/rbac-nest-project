// src/modules/employee/application/listeners/core-employee-imported.listener.ts
import { ILogger, LOGGER_TOKEN } from "@core/shared/application/ports/logger.port";
import { EventHandler } from "@core/shared/infrastructure/event-bus/decorators/event-handler.decorator";
import { IEmployeeRepository } from "@modules/employee/domain/repositories/employee.repository";
import { CoreEmployeeImportedEvent } from "@modules/org-structure/domain/events/core-employee-imported.event";
import { Inject, Injectable } from "@nestjs/common";
import { Employee } from "../../domain/entities/employee.entity";

@Injectable()
export class CoreEmployeeImportedListener {
    constructor(
        @Inject(IEmployeeRepository) private readonly employeeRepo: IEmployeeRepository,
        @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    ) { }

    @EventHandler(CoreEmployeeImportedEvent)
    async handle(event: CoreEmployeeImportedEvent) {
        const { payload } = event;

        // Khởi tạo Entity
        const employee = new Employee({
            organizationId: payload.organizationId,
            userId: payload.userId,
            employeeCode: payload.employeeCode,
            fullName: payload.fullName,
            locationId: payload.locationId,
            positionId: payload.positionId,
        });

        await this.employeeRepo.save(employee);
        this.logger.info(`✅ Đã khởi tạo hồ sơ nhân sự cho: ${payload.fullName}`);
    }
}

