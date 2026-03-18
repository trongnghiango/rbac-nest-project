import { Controller, Post, Get, Body, UseGuards, Param, ParseIntPipe } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
// import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard'; // (Uncomment nếu có auth)
import { EmployeeService } from '../../application/services/employee.service';
import { CreateEmployeeDto } from '../../application/dtos/create-employee.dto';
import { ProvisionAccountDto } from '@modules/employee/application/dtos/provision-account.dto';

@ApiTags('Employee Management (Hồ sơ Nhân sự)')
@ApiBearerAuth()
@Controller('employees')
// @UseGuards(JwtAuthGuard)
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
    @ApiOperation({ summary: 'Lấy danh sách toàn bộ nhân viên' })
    async getAllEmployees() {
        return this.employeeService.getAllEmployees();
    }
}
