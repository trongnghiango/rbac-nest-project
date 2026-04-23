// src/modules/user/domain/types/user-contexts.type.ts

export interface UserPersonalInfo {
    fullName?: string;
    avatarUrl?: string;
    bio?: string;
    phoneNumber?: string;
    settings?: {
        theme?: 'dark' | 'light';
        language?: string;
        notifications?: boolean;
        [key: string]: any; // Cho phép mở rộng cài đặt UI
    };
}

export interface EmployeeContext {
    id: number;
    employeeCode: string;
    fullName: string;
    position?: string;
    department?: string;
    departmentCode?: string;
    location?: string;
    organization_id?: number;
}

export interface OrganizationContext {
    id: number;
    companyName: string;
    taxCode?: string;
    industry?: string;
    status?: string;
}

// Đây là "profiles" cũ được cấu trúc lại thành "context"
export interface UserBusinessContext {
    employee?: EmployeeContext;
    organization?: OrganizationContext;
    student?: any; // Có thể định nghĩa thêm khi làm module Elearning
}
