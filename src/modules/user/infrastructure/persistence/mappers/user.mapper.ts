
import { InferInsertModel } from 'drizzle-orm';
import { AssociatedProfiles, User } from '../../../domain/entities/user.entity';
import { users } from '@database/schema';

// Type insert cho bảng users (flat)
type UserInsert = InferInsertModel<typeof users>;

export class UserMapper {
  /**
   * Map từ kết quả query Drizzle (có Relation) sang Domain Entity
   * `raw` ở đây là `any` vì type của Drizzle Query Builder rất phức tạp để define tĩnh
   */
  static toDomain(raw: any): User | null {
    if (!raw) return null;

    // ✅ Logic Strict RBAC: Map từ bảng nối ra mảng string
    const roles: string[] = raw.userRoles
      ? raw.userRoles.map((ur: any) => ur.role?.name || '').filter(Boolean)
      : [];

    // ✅ LOGIC MỚI: Khởi tạo cái túi rỗng
    const businessProfiles: AssociatedProfiles = {};

    // 1. Nhặt dữ liệu HRM (Nếu User là Nhân viên)
    if (raw.employeeProfile) {
      businessProfiles.employee = {
        employeeCode: raw.employeeProfile.employeeCode,
        fullName: raw.employeeProfile.fullName,
        position: raw.employeeProfile.position?.name || raw.employeeProfile.position?.jobTitle?.name,
        departmentCode: raw.employeeProfile.position?.orgUnit?.code,
        location: raw.employeeProfile.location?.name,
      };
    }

    // 2. Nhặt dữ liệu CRM (Nếu User là Đối tác/Doanh nghiệp B2B)
    if (raw.organizationProfile) {
      businessProfiles.organization = {
        companyName: raw.organizationProfile.companyName,
        taxCode: raw.organizationProfile.taxCode,
        industry: raw.organizationProfile.industry,
        status: raw.organizationProfile.status,
      };
    }

    // ✅ TRUYỀN DƯỚI DẠNG OBJECT
    return new User({
      id: raw.id,
      username: raw.username,
      email: raw.email || undefined,
      hashedPassword: raw.hashedPassword || undefined,
      fullName: raw.fullName || undefined,
      isActive: raw.isActive ?? true,
      roles: roles,
      telegramId: raw.telegramId || undefined,
      phoneNumber: raw.phoneNumber || undefined,
      avatarUrl: raw.avatarUrl || undefined,
      profile: (raw.profile as any) || undefined,
      profiles: businessProfiles, // Truyền cái túi vào
      createdAt: raw.createdAt || undefined,
      updatedAt: raw.updatedAt || undefined,
    });
  }

  /**
   * Map từ Domain sang Persistence (Chỉ map các field thuộc bảng `users`)
   * Không map `roles` vì roles nằm ở bảng `user_roles`
   */
  static toPersistence(domain: User): UserInsert {
    return {
      id: domain.id,
      username: domain.username,
      email: domain.email || null,
      hashedPassword: domain.hashedPassword || null,
      isActive: domain.isActive,
      telegramId: domain.telegramId || null, // ✅ Map TelegramId
      createdAt: domain.createdAt || new Date(),
      updatedAt: domain.updatedAt || new Date(),
    };
  }
}