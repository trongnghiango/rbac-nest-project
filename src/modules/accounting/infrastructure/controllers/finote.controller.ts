// src/modules/accounting/infrastructure/controllers/finote.controller.ts
import {
    Controller,
    Post,
    Body,
    UseGuards,
    BadRequestException
} from '@nestjs/common';
import {
    ApiTags,
    ApiOperation,
    ApiResponse,
    ApiBearerAuth,
    ApiBody
} from '@nestjs/swagger';
import { FinoteService } from '../../application/services/finote.service';
import { CreateFinoteDto } from '../../application/dtos/create-finote.dto';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '@modules/rbac/infrastructure/guards/permission.guard';
import { Permissions } from '@modules/rbac/infrastructure/decorators/permission.decorator';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { User } from '@modules/user/domain/entities/user.entity';

@ApiTags('Accounting (Kế toán & Tài chính)')
@ApiBearerAuth()
@Controller('accounting/finotes')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class FinoteController {
    constructor(private readonly finoteService: FinoteService) { }

    @Post()
    @Permissions('finote:create') // Yêu cầu quyền tạo phiếu
    @ApiOperation({
        summary: 'Tạo phiếu Thu/Chi (Finote) mới',
        description: 'API tạo phiếu thu (INCOME) hoặc chi (EXPENSE). Sau khi tạo thành công, hệ thống sẽ trigger Event để tự động sinh file PDF.'
    })
    @ApiBody({ type: CreateFinoteDto })
    @ApiResponse({ status: 201, description: 'Tạo phiếu thành công và trả về thông tin phiếu.' })
    @ApiResponse({ status: 400, description: 'Dữ liệu đầu vào (Validation) không hợp lệ.' })
    async createFinote(
        @Body() dto: CreateFinoteDto,
        @CurrentUser() user: User
    ) {
        if (!user.id) {
            throw new BadRequestException('Không tìm thấy thông tin định danh của người dùng');
        }

        // TÌM RA ĐIỂM SỬA: Lấy Employee ID từ Profile Context của User
        const employeeId = user.profileContext?.employee?.id;
        if (!employeeId) {
            throw new BadRequestException('Tài khoản của bạn chưa được liên kết với Hồ sơ Nhân sự (Employee Profile) nên không thể tạo phiếu!');
        }

        // Truyền employeeId vào service thay vì user.id
        const result = await this.finoteService.createFinote(dto, employeeId);
        return result;
    }
}
