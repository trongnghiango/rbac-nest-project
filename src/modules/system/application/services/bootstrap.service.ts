import { Injectable } from '@nestjs/common';
import { User } from '@modules/user/domain/entities/user.entity';

@Injectable()
export class BootstrapService {
  /**
   * Tạo App Context ban đầu cho Frontend
   * Sau này sẽ inject PermissionService để tính toán quyền thực tế
   */
  getAppContext(user: User) {
    return {
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.personalInfo?.fullName || user.username,
        avatar: user.personalInfo?.avatarUrl || null,
      },
      configs: {
        theme: 'system',
        language: 'vi-VN',
        timezone: 'Asia/Ho_Chi_Minh',
        currency: 'VND',
        dateFormat: 'DD/MM/YYYY',
      },
      notifications: {
        unreadCount: 0,
      },
      // Logic phân quyền UI được cô lập tại đây
      permissions: this.getUiPermissions(user),
    };
  }

  private getUiPermissions(user: User) {
    // Tạm thời mock logic, sau này mapping từ RbacModule
    return {
      canViewDashboard: true,
      canManageLeads: true,
      canManageContracts: true,
      canApproveFinotes: false,
    };
  }
}
