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
      canApproveFinotes: user.username === 'superadmin' || user.username.includes('manager'),
    };
  }

  /**
   * Trả về báo cáo nhanh cho cấp quản lý (My Team Summary)
   * Chẻ số liệu từ CRM và Accounting
   */
  async getTeamSummary(user: User) {
    // Logic thực tế sẽ gọi sang LeadRepository và FinoteRepository
    // Tạm thời mock dữ liệu "chuẩn" để Frontend build UI
    return {
      period: '2026-04',
      leads: {
        totalNew: 12,
        totalConverted: 5,
        conversionRate: '41.6%',
        pendingAssignment: 3
      },
      accounting: {
        pendingApprovals: 8,
        totalPendingAmount: 150000000,
        currency: 'VND'
      },
      staffPerformance: [
        { name: 'Nguyễn Văn A', activeLeads: 5, wonLeads: 2 },
        { name: 'Trần Thị B', activeLeads: 8, wonLeads: 3 }
      ]
    };
  }
}
