import { BadRequestException, Body, Controller, Get, Inject, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../../rbac/infrastructure/guards/permission.guard';
import { Permissions } from '../../rbac/infrastructure/decorators/permission.decorator';
import { Public } from '../../auth/infrastructure/decorators/public.decorator';
import { CurrentUser } from '../../auth/infrastructure/decorators/current-user.decorator';
import { ApiBearerAuth, ApiBody, ApiOperation } from '@nestjs/swagger';
import type { ILogger } from '@core/shared/application/ports/logger.port';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { PERMISSIONS } from '@modules/rbac/domain/constants/rbac.constants';
import { SeedCustomerDto } from '../dtos/seed-customer.dto';
import * as schema from '@database/schema';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE } from '@database/drizzle.provider';

@Controller('test')
@ApiBearerAuth()
export class TestController {
  constructor(
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    @Inject(DRIZZLE) private readonly db: NodePgDatabase<typeof schema>,

  ) { }

  @Public()
  @Get('health')
  healthCheck() {
    this.logger.info('ciquan');
    return {
      status: 'OK',
      timestamp: new Date(),
      service: 'RBAC System',
      version: '1.0.0',
    };
  }

  @Get('protected')
  @UseGuards(JwtAuthGuard)
  protectedRoute(@CurrentUser() user: any) {
    return {
      message: 'This is a protected route',
      user: {
        id: user.id,
        username: user.username,
        roles: user.roles,
      },
    };
  }

  @Get('admin-only')
  @UseGuards(JwtAuthGuard, PermissionGuard)
  @Permissions('rbac:manage')
  adminOnly(@CurrentUser() user: any) {
    return {
      message: 'This is admin-only route',
      user: {
        id: user.id,
        username: user.username,
      },
    };
  }

  @Get('user-management')
  @UseGuards(JwtAuthGuard, PermissionGuard)
  @Permissions('user:manage')
  userManagement(@CurrentUser() user: any) {
    return {
      message: 'You have user management permission',
      user: {
        id: user.id,
        username: user.username,
      },
    };
  }

  // =========================================================================
  // 🚀 API SANDBOX: DÙNG ĐỂ BẬT/TẮT TEST TỪNG QUYỀN
  // =========================================================================
  @Get('sandbox-permissions')
  @UseGuards(JwtAuthGuard, PermissionGuard)
  @Permissions(
    // 💡 HƯỚNG DẪN: 
    // Hãy MỞ COMMENT (xóa dấu //) ở đúng 1 dòng mà bạn muốn test.
    // Sau khi test xong, hãy comment lại và mở dòng khác để thử.

    // --- 1. NHÓM QUYỀN HỆ THỐNG (SYSTEM & RBAC) ---
    // PERMISSIONS.SYSTEM_CONFIG,      // Chỉ ADMIN hoặc SUPER_ADMIN mới qua được
    // PERMISSIONS.RBAC_MANAGE,        // Chỉ IT_ADMIN hoặc SUPER_ADMIN
    // PERMISSIONS.AUDIT_VIEW,         // Chỉ QA_AUDITOR hoặc ADMIN

    // --- 2. NHÓM QUYỀN TÀI KHOẢN (USER) ---
    // PERMISSIONS.USER_MANAGE,        // ADMIN, IT_ADMIN
    // PERMISSIONS.USER_READ,          // STAFF, MANAGER (Xem danh bạ)

    // --- 3. NHÓM QUYỀN NHÂN SỰ & TỔ CHỨC (HRM) ---
    // PERMISSIONS.ORG_MANAGE,         // ADMIN
    // PERMISSIONS.ORG_READ,           // STAFF, MANAGER (Xem sơ đồ công ty)
    // PERMISSIONS.EMPLOYEE_MANAGE,    // ADMIN (HR)
    // PERMISSIONS.EMPLOYEE_UPDATE,    // MANAGER (Cập nhật nhân sự cấp dưới)
    // PERMISSIONS.EMPLOYEE_READ,      // MANAGER

    // --- 4. NHÓM QUYỀN NGHIỆP VỤ (BOOKING/ĐƠN HÀNG) ---
    // PERMISSIONS.BOOKING_MANAGE,     // MANAGER (Quản lý toàn bộ đơn của phòng)
    // PERMISSIONS.BOOKING_CREATE,     // STAFF (Lên đơn mới)
    // PERMISSIONS.BOOKING_READ,       // STAFF (Xem đơn của mình)
    // PERMISSIONS.BOOKING_UPDATE,     // STAFF (Sửa đơn của mình)

    // --- 5. TÍNH NĂNG MỚI (TEST MAGIC STRING) ---
    // 'payroll:approve',              // Bạn có thể gõ string bất kỳ vào đây để test!
  )
  testSandbox(@CurrentUser() user: any) {
    return {
      success: true,
      message: '🎉 CHÚC MỪNG! BẠN ĐÃ VƯỢT QUA GUARD BẢO VỆ.',
      note: 'Nếu bạn thấy dòng này, nghĩa là tài khoản của bạn ĐÃ CÓ quyền vừa được mở comment.',
      user_info: {
        id: user.id,
        username: user.username,
        roles: user.roles, // Các role đang sở hữu
      },
    };
  }


  @Public()
  @Post('seed-customer')
  @ApiOperation({ summary: 'Tạo nhanh 1 Khách hàng (Org + Contact) để test' })
  @ApiBody({ type: SeedCustomerDto })
  async seedCustomer(@Body() dto: SeedCustomerDto) {
    try {
      // Dùng Transaction để đảm bảo tạo Org và Contact cùng lúc thành công
      const result = await this.db.transaction(async (tx) => {
        // 1. Tạo Organization
        const [newOrg] = await tx.insert(schema.organizations).values({
          company_name: dto.companyName,
          tax_code: dto.taxCode,
          industry: dto.industry,
          address: dto.address,
          status: (dto.status || 'ACTIVE') as any,
          is_internal: false // Chắc chắn đây là khách ngoài
        }).returning();

        // 2. Tạo Contact móc nối vào Organization
        const [newContact] = await tx.insert(schema.contacts).values({
          organization_id: newOrg.id,
          full_name: dto.contactName,
          phone: dto.contactPhone,
          email: dto.contactEmail,
          job_title: dto.contactJobTitle,
          is_primary: true
        }).returning();

        return { organization: newOrg, primaryContact: newContact };
      });

      return {
        success: true,
        message: 'Tạo dữ liệu Khách hàng B2B mẫu thành công!',
        data: result
      };
    } catch (error: any) {
      if (error.code === '23505') {
        throw new BadRequestException('Lỗi: Email hoặc Mã số thuế này đã tồn tại trong hệ thống!');
      }
      throw error;
    }
  }


  @Public()
  @Post('seed-mock-lead')
  @ApiOperation({ summary: 'Tạo 1 Lead nháp để test luồng CRM' })
  async seedMockLead() {
    // 1. Tạo 1 Organization nháp
    const [org] = await this.db.insert(schema.organizations).values({
      company_name: 'Anh Long (Chưa có cty)',
      status: 'PROSPECT' as any
    }).returning();

    // 2. Tạo 1 Lead gắn vào Org đó
    const [lead] = await this.db.insert(schema.leads).values({
      organization_id: org.id,
      title: 'Tư vấn thành lập công ty',
      stage: 'NEW' as any
    }).returning();

    return { message: 'Tạo Lead nháp thành công', leadId: lead.id, orgId: org.id };
  }

}
