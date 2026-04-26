import { Injectable, Inject, BadRequestException, NotFoundException } from '@nestjs/common';
import { IOrgStructureRepository } from '@modules/org-structure/domain/repositories/org-structure.repository';
import { IEmployeeRepository } from '../../domain/repositories/employee.repository';
import { CreateEmployeeDto } from '../dtos/create-employee.dto';
import { ProvisionAccountDto } from '../dtos/provision-account.dto';
import { CORE_ROLES } from '@modules/rbac/domain/constants/rbac.constants';
import { User } from '@modules/user/domain/entities/user.entity';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { EmployeeAccountRequestedEvent } from '@modules/employee/domain/events/employee-account-requested.event';
import { Employee } from '../../domain/entities/employee.entity'; // <-- Import Entity

@Injectable()
export class EmployeeService {
    constructor(
        @Inject(IEmployeeRepository) private employeeRepo: IEmployeeRepository,
        @Inject(IOrgStructureRepository) private orgRepo: IOrgStructureRepository,
        @Inject(IEventBus) private readonly eventBus: IEventBus,
    ) { }

    // THÊM: organizationId vào param vì Entity Employee BẮT BUỘC phải có organizationId
    async onboardNewEmployee(dto: CreateEmployeeDto, organizationId: number) {
        const position = await this.orgRepo.findPositionById(dto.positionId);
        if (!position) {
            throw new BadRequestException('Vị trí bổ nhiệm không tồn tại trong sơ đồ tổ chức.');
        }
        if (!position.isActive) {
            throw new BadRequestException('Vị trí này hiện đang bị đóng băng tuyển dụng.');
        }

        // FIX 1: Khởi tạo Entity thay vì dùng Raw Object
        const newEmployee = new Employee({
            organizationId: organizationId,
            userId: dto.userId || undefined,
            employeeCode: dto.employeeCode,
            fullName: dto.fullName,
            locationId: dto.locationId,
            positionId: position.id,
        });

        return await this.employeeRepo.save(newEmployee);
    }

    async provisionUserAccount(employeeId: number, dto: ProvisionAccountDto) {
        const employee = await this.employeeRepo.findById(employeeId);
        if (!employee) throw new NotFoundException('Không tìm thấy hồ sơ nhân viên');
        if (employee.userId) throw new BadRequestException('Nhân viên này đã có tài khoản ERP');

        const rawUsername = dto.username || employee.employeeCode;
        const finalUsername = rawUsername.trim().toLowerCase();

        await this.eventBus.publish(
            new EmployeeAccountRequestedEvent(String(employeeId), {
                employeeId: employee.id!,
                email: dto.email,
                username: finalUsername,
                fullName: employee.fullName,
                organizationId: employee.organizationId, // FIX 2: Sửa organizationId thành organizationId
            }),
        );

        return {
            success: true,
            message: 'Yêu cầu cấp tài khoản đã được tiếp nhận và đang xử lý.',
        };
    }

    async getAllEmployees(currentUser: User) {
        if (!currentUser) {
            throw new BadRequestException('Thông tin người dùng không hợp lệ');
        }

        const userRoles = currentUser.roles || [];
        if (userRoles.includes(CORE_ROLES.SUPER_ADMIN)) {
            return this.employeeRepo.findAll();
        }

        const employeeProfile = currentUser.profileContext?.employee;
        if (!employeeProfile || !employeeProfile.departmentCode) {
            return [];
        }

        const unit = await this.orgRepo.findByCode(employeeProfile.departmentCode);
        if (!unit || !unit.path) {
            return [];
        }

        const pathParts = unit.path.split('/').filter(Boolean);
        const rootCompanyId = pathParts[0];
        const rootPath = `/${rootCompanyId}/`;
        return this.employeeRepo.findAll({ orgPath: rootPath });
    }
}
