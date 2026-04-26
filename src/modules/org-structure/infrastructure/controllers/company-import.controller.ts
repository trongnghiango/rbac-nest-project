import { Controller, Post, UseInterceptors, UploadedFile, UseGuards, BadRequestException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiConsumes, ApiBody } from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '@modules/rbac/infrastructure/guards/permission.guard';
import { Permissions } from '@modules/rbac/infrastructure/decorators/permission.decorator';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { User } from '@modules/user/domain/entities/user.entity';
import { CompanyImportService } from '../../application/services/company-import.service';

@ApiTags('Company Setup (Khởi tạo hệ thống)')
@ApiBearerAuth()
@Controller('company/setup')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class CompanyImportController {
    constructor(private readonly importService: CompanyImportService) { }

    @ApiOperation({ summary: 'Khởi tạo Nhân sự Chủ chốt từ file CSV' })
    @ApiConsumes('multipart/form-data')
    @ApiBody({ schema: { type: 'object', properties: { file: { type: 'string', format: 'binary' } } } })
    @Post('import-core-employees')
    @Permissions('system:config')
    @UseInterceptors(FileInterceptor('file'))
    async importCoreCompany(
        @UploadedFile() file: Express.Multer.File,
        @CurrentUser() admin: User
    ) {
        if (!file) throw new BadRequestException('Vui lòng đính kèm file CSV');
        if (!file.originalname.endsWith('.csv')) throw new BadRequestException('Chỉ chấp nhận định dạng .csv');

        // Lấy organizationId từ profileContext của người đang upload (Admin)
        const organizationId = admin.profileContext?.employee?.organizationId;

        if (!organizationId) {
            throw new BadRequestException('Tài khoản của bạn chưa được liên kết với bất kỳ công ty nào, không thể upload file nhân sự!');
        }

        // Truyền đủ 3 tham số: fileBuffer, adminId, và organizationId
        const result = await this.importService.importCoreCompany(file.buffer, admin.id!, organizationId);
        return result;
    }
}