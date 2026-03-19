import { Controller, Get, Inject, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../../rbac/infrastructure/guards/permission.guard';
import { Permissions } from '../../rbac/infrastructure/decorators/permission.decorator';
import { Public } from '../../auth/infrastructure/decorators/public.decorator';
import { CurrentUser } from '../../auth/infrastructure/decorators/current-user.decorator';
import { ApiBearerAuth } from '@nestjs/swagger';
import type { ILogger } from '@core/shared/application/ports/logger.port';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { PERMISSIONS } from '@modules/rbac/domain/constants/rbac.constants';

@Controller('test')
@ApiBearerAuth()
export class TestController {
  constructor(@Inject(LOGGER_TOKEN) private readonly logger: ILogger) { }

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

}
