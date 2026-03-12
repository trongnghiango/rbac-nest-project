import { Controller, Post, UseInterceptors, UploadedFile, UseGuards, BadRequestException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiConsumes, ApiBody } from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '@modules/rbac/infrastructure/guards/permission.guard';
import { Permissions } from '@modules/rbac/infrastructure/decorators/permission.decorator';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { User } from '../../domain/entities/user.entity';
import { UserImportService } from '../../application/services/user-import.service';

@ApiTags('Users Management')
@ApiBearerAuth()
@Controller('users/data')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class UserImportController {
    constructor(private userImportService: UserImportService) { }

    @ApiOperation({ summary: 'Bulk Import Users từ file CSV' })
    @ApiConsumes('multipart/form-data')
    @ApiBody({ schema: { type: 'object', properties: { file: { type: 'string', format: 'binary' } } } })
    @Post('import')
    @Permissions('user:manage') // Yêu cầu quyền quản lý User
    @UseInterceptors(FileInterceptor('file'))
    async importUsers(
        @UploadedFile() file: Express.Multer.File,
        @CurrentUser() admin: User
    ) {
        if (!file) throw new BadRequestException('Vui lòng đính kèm file CSV');
        if (!file.originalname.endsWith('.csv')) throw new BadRequestException('Chỉ chấp nhận định dạng .csv');

        const content = file.buffer.toString('utf-8');
        const result = await this.userImportService.importFromCsv(content, admin.id);

        return result;
    }
}
