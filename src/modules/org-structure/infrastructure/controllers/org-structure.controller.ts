import { Controller, Get, Post, Patch, Delete, Param, Body, ParseIntPipe, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { OrgStructureService } from '../../application/services/org-structure.service';
import { CreateOrgUnitRequestDto, UpdateOrgUnitRequestDto } from '../dtos/org-unit.request.dto';
import { Permissions } from '@modules/rbac/infrastructure/decorators/permission.decorator';
import { ORG_PERMISSIONS } from '@modules/org-structure/domain/constants/org.permissions';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '@modules/rbac/infrastructure/guards/permission.guard';
import { PERMISSIONS } from '@modules/rbac/domain/constants/rbac.constants';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { OrgUnitResponseDto } from '../dtos/org-unit.response.dto';
import { User } from '@modules/user/domain/entities/user.entity';
import { BadRequestException } from '@nestjs/common';

@ApiBearerAuth()
@UseGuards(JwtAuthGuard, PermissionGuard) // Uncomment khi ghép Auth
@ApiTags('Organization Structure (Cơ cấu tổ chức)') // Gom nhóm API trên Swagger
@Controller('org-structure')
export class OrgStructureController {
    constructor(private readonly orgService: OrgStructureService) { }

    @Get('tree')
    @Permissions(ORG_PERMISSIONS.READ) //'org:read'
    @ApiOperation({
        summary: 'Lấy toàn bộ sơ đồ tổ chức (Organization Tree)',
        description: 'Trả về dữ liệu cây phân cấp (Hierarchical Tree) của toàn bộ công ty. Các phòng ban con được chứa trong mảng `children`.'
    })
    @ApiResponse({
        status: 200,
        description: 'Cây sơ đồ tổ chức trả về thành công.',
        // Optional: Bạn có thể viết hardcode 1 example response nếu muốn Swagger hiển thị cực đẹp
        schema: {
            example: {
                data: [
                    {
                        "id": 1,
                        "parentId": null,
                        "type": "COMPANY",
                        "code": "HQ",
                        "name": "Trụ sở chính",
                        "isActive": true,
                        "children": [
                            {
                                "id": 2,
                                "parentId": 1,
                                "type": "DEPARTMENT",
                                "code": "PB-TECH",
                                "name": "Phòng Công Nghệ",
                                "isActive": true,
                                "children": []
                            }
                        ]
                    }
                ]
            }
        }
    })
    async getOrgTree() {
        const tree = await this.orgService.getOrganizationTree();
        return { data: OrgUnitResponseDto.fromTree(tree) };
    }

    @Post('units')
    @Permissions(ORG_PERMISSIONS.MANAGE)// @Permissions('org:create')
    @ApiOperation({
        summary: 'Tạo mới một Đơn vị/Phòng ban',
        description: 'Thêm một phòng ban hoặc chi nhánh mới vào sơ đồ tổ chức. Truyền `parentId` nếu nó trực thuộc một phòng ban khác.'
    })
    @ApiBody({ type: CreateOrgUnitRequestDto }) // Liên kết với DTO
    @ApiResponse({ status: 201, description: 'Phòng ban được tạo thành công.' })
    @ApiResponse({ status: 400, description: 'Dữ liệu đầu vào không hợp lệ (Validation Error).' })
    @ApiResponse({ status: 404, description: 'Phòng ban cha (parentId) không tồn tại.' })
    async createUnit(
        @Body() dto: CreateOrgUnitRequestDto,
        @CurrentUser() user: User,
    ) {
        // Tự động lấy ID Công ty của người tạo truyền xuống Service
        const orgId = user.profileContext?.employee?.organizationId;

        if (!orgId) {
            throw new BadRequestException('Tài khoản của bạn chưa thuộc tổ chức nào, không thể tạo phòng ban!');
        }

        const newUnit = await this.orgService.createUnit({
            ...dto,
            organizationId: orgId
        });
        return { data: OrgUnitResponseDto.fromDomain(newUnit) };
    }

    @Patch('units/:id')
    @Permissions(ORG_PERMISSIONS.UPDATE) // @Permissions('org:update')
    @ApiOperation({ summary: 'Cập nhật thông tin Phòng ban' })
    @ApiParam({ name: 'id', description: 'ID của phòng ban cần cập nhật', example: 2 })
    @ApiBody({ type: UpdateOrgUnitRequestDto })
    @ApiResponse({ status: 200, description: 'Cập nhật thành công.' })
    @ApiResponse({ status: 404, description: 'Không tìm thấy phòng ban với ID cung cấp.' })
    async updateUnit(@Param('id', ParseIntPipe) id: number, @Body() dto: UpdateOrgUnitRequestDto) {
        const updatedUnit = await this.orgService.updateUnit(id, dto);
        return { data: OrgUnitResponseDto.fromDomain(updatedUnit) };
    }

    @Delete('units/:id')
    // @Permissions('org:delete')
    @ApiOperation({
        summary: 'Xóa Phòng ban',
        description: 'Lưu ý: Không thể xóa một phòng ban nếu nó đang chứa các phòng ban con (nhóm con) bên trong do ràng buộc khóa ngoại (Hard FK).'
    })
    @ApiParam({ name: 'id', description: 'ID của phòng ban cần xóa', example: 2 })
    @ApiResponse({ status: 200, description: 'Xóa thành công.' })
    @ApiResponse({ status: 400, description: 'Không thể xóa (Thường do đang chứa phòng ban con).' })
    async deleteUnit(@Param('id', ParseIntPipe) id: number) {
        return this.orgService.deleteUnit(id);
    }

    @Post('tools/migrate-paths')
    @Permissions(PERMISSIONS.SYSTEM_CONFIG)
    @ApiOperation({ summary: 'Tool chạy 1 lần: Tự động tính toán trường path cho data cũ' })
    async runMigration() {
        return this.orgService.migrateAllNullPaths();
    }
}
