import { Controller, Post, Get, Body, UseGuards, Param, ParseIntPipe, UnauthorizedException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
// import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard'; // (Uncomment nếu có auth)
import { EmployeeService } from '../../application/services/employee.service';
import { CreateEmployeeDto } from '../../application/dtos/create-employee.dto';
import { ProvisionAccountDto } from '@modules/employee/application/dtos/provision-account.dto';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { User } from '@modules/user/domain/entities/user.entity';
import { Permissions } from '@modules/rbac/infrastructure/decorators/permission.decorator';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '@modules/rbac/infrastructure/guards/permission.guard';

@ApiTags('Employee Management (Hồ sơ Nhân sự)')
@ApiBearerAuth()
@Controller('employees')
// @UseGuards(JwtAuthGuard)
@UseGuards(JwtAuthGuard, PermissionGuard)
export class EmployeeController {
    constructor(private readonly employeeService: EmployeeService) { }

    @Post('onboard')
    @ApiOperation({ summary: 'Tiếp nhận nhân viên mới (Onboarding)' })
    @ApiResponse({ status: 201, description: 'Tiếp nhận thành công' })
    @ApiResponse({ status: 400, description: 'Vị trí bổ nhiệm không hợp lệ' })
    async onboardEmployee(@Body() dto: CreateEmployeeDto) {
        return this.employeeService.onboardNewEmployee(dto);
    }

    @Post(':id/provision-account')
    @ApiOperation({ summary: 'Cấp tài khoản ERP cho nhân viên đã onboard' })
    @ApiResponse({ status: 201, description: 'Cấp tài khoản thành công. Trả về thông tin đăng nhập.' })
    @ApiResponse({ status: 400, description: 'Trùng username hoặc nhân viên đã có tài khoản.' })
    async provisionAccount(
        @Param('id', ParseIntPipe) id: number,
        @Body() dto: ProvisionAccountDto // Sử dụng DTO ở đây
    ) {
        return this.employeeService.provisionUserAccount(id, dto);
    }

    @Get()
    @Permissions('employee:read') // Check quyền cơ bản trong bảng permissions
    @ApiOperation({ summary: 'Lấy danh sách nhân viên theo phân quyền' })
    async getAllEmployees(@CurrentUser() user: User) {
        if (!user) {
            // Nếu vào đây nghĩa là JwtAuthGuard có vấn đề hoặc Token hợp lệ nhưng User bị xóa trong DB
            throw new UnauthorizedException('Không tìm thấy thông tin người dùng trong phiên làm việc');
        }
        // Truyền user đang login vào service
        return this.employeeService.getAllEmployees(user);
    }
}
