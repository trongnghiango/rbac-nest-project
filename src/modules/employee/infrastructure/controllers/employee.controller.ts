// src/modules/employee/infrastructure/controllers/employee.controller.ts
import { Controller, Post, Get, Body, UseGuards, Param, ParseIntPipe, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { EmployeeService } from '../../application/services/employee.service';
import { CreateEmployeeRequestDto } from '../dtos/create-employee.request.dto';
import { ProvisionAccountRequestDto } from '../dtos/provision-account.request.dto';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { User } from '@modules/user/domain/entities/user.entity';
import { Permissions } from '@modules/rbac/infrastructure/decorators/permission.decorator';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '@modules/rbac/infrastructure/guards/permission.guard';
import { EmployeeResponseDto } from '../dtos/employee-response.dto'; // <-- Import DTO

@ApiTags('Employee Management (Hồ sơ Nhân sự)')
@ApiBearerAuth()
@Controller('employees')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class EmployeeController {
    constructor(private readonly employeeService: EmployeeService) { }

    @Post('onboard')
    @ApiOperation({ summary: 'Tiếp nhận nhân viên mới (Onboarding)' })
    @ApiResponse({ status: 201, description: 'Tiếp nhận thành công', type: EmployeeResponseDto })
    @ApiResponse({ status: 400, description: 'Vị trí bổ nhiệm không hợp lệ' })
    async onboardEmployee(
        @Body() dto: CreateEmployeeRequestDto,
        @CurrentUser() user: User
    ): Promise<EmployeeResponseDto> {
        const orgId = user.profileContext?.employee?.organizationId || 1;

        if (!orgId) {
            throw new BadRequestException('Tài khoản của bạn chưa được liên kết với Công ty nào.');
        }

        const employeeEntity = await this.employeeService.onboardNewEmployee(dto, orgId);
        return EmployeeResponseDto.fromDomain(employeeEntity); // <-- Trả về DTO
    }

    @Post(':id/provision-account')
    @ApiOperation({ summary: 'Cấp tài khoản ERP cho nhân viên đã onboard' })
    @ApiResponse({ status: 201, description: 'Cấp tài khoản thành công. Trả về thông tin đăng nhập.' })
    @ApiResponse({ status: 400, description: 'Trùng username hoặc nhân viên đã có tài khoản.' })
    async provisionAccount(
        @Param('id', ParseIntPipe) id: number,
        @Body() dto: ProvisionAccountRequestDto
    ) {
        return this.employeeService.provisionUserAccount(id, dto);
    }

    @Get()
    @Permissions('employee:read')
    @ApiOperation({ summary: 'Lấy danh sách nhân viên theo phân quyền' })
    @ApiResponse({ status: 200, type: [EmployeeResponseDto] })
    async getAllEmployees(@CurrentUser() user: User): Promise<EmployeeResponseDto[]> {
        if (!user) {
            throw new UnauthorizedException('Không tìm thấy thông tin người dùng trong phiên làm việc');
        }

        const employees = await this.employeeService.getAllEmployees(user);
        // <-- Map danh sách Entity sang DTO
        return employees.map(emp => EmployeeResponseDto.fromDomain(emp));
    }
}
