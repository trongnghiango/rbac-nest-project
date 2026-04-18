import { InferInsertModel } from 'drizzle-orm';
import { User } from '../../../domain/entities/user.entity';
import { users } from '@database/schema';
import {
  EmployeeContext,
  OrganizationContext,
  UserBusinessContext,
  UserPersonalInfo
} from '../../../domain/types/user-contexts.type';

type UserInsert = InferInsertModel<typeof users>;

export class UserMapper {
  static toDomain(raw: any): User | null {
    if (!raw) return null;

    // 1. Map Roles (Strict RBAC)
    const roles: string[] = raw.userRoles
      ? raw.userRoles.map((ur: any) => ur.role?.name || '').filter(Boolean)
      : [];

    // 2. Map Personal Info (Từ bảng user_metadata Join 1-1)
    const personalInfo: UserPersonalInfo = {
      fullName: raw.metadata?.fullName || raw.fullName, // Fallback nếu metadata chưa có
      avatarUrl: raw.metadata?.avatarUrl,
      bio: raw.metadata?.bio,
      phoneNumber: raw.metadata?.phoneNumber,
      settings: raw.metadata?.settings,
    };

    // 3. Map Business Context (HRM, CRM, v.v.)
    const profileContext: UserBusinessContext = {};


    if (raw.employeeProfile) {
      profileContext.employee = {
        id: raw.employeeProfile.id,
        employeeCode: raw.employeeProfile.employeeCode,
        fullName: raw.employeeProfile.fullName,
        position: raw.employeeProfile.position?.name,
        department: raw.employeeProfile.position?.orgUnit?.name,
        departmentCode: raw.employeeProfile.position?.orgUnit?.code, // ✅ Nhặt code từ DB Join
        location: raw.employeeProfile.location?.name,
      };
    }

    if (raw.organizationProfile) {
      profileContext.organization = {
        id: raw.organizationProfile.id,
        companyName: raw.organizationProfile.companyName,
        taxCode: raw.organizationProfile.taxCode,
        industry: raw.organizationProfile.industry,
        status: raw.organizationProfile.status,
      };
    }

    // 4. Khởi tạo Entity với Object Pattern sạch sẽ
    return new User({
      id: raw.id,
      username: raw.username,
      email: raw.email || undefined,
      hashedPassword: raw.hashedPassword || undefined,
      isActive: raw.isActive ?? true,
      roles: roles,
      telegramId: raw.telegramId || undefined,

      // personalInfo: personalInfo,
      personalInfo: {
        fullName: raw.metadata?.fullName || raw.fullName, // 👈 metadata lấy từ join
        avatarUrl: raw.metadata?.avatarUrl,
        phoneNumber: raw.metadata?.phoneNumber,
        settings: raw.metadata?.settings,
      },
      profileContext: profileContext,
      createdAt: raw.createdAt || undefined,
      updatedAt: raw.updatedAt || undefined,
    });
  }

  static toPersistence(domain: User): UserInsert {
    return {
      id: domain.id,
      username: domain.username,
      email: domain.email || null,
      hashedPassword: domain.hashedPassword || null,
      isActive: domain.isActive,
      telegramId: domain.telegramId || null,
      createdAt: domain.createdAt || new Date(),
      updatedAt: domain.updatedAt || new Date(),
    };
  }
}
