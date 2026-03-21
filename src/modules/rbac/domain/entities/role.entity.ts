import { Permission } from './permission.entity';

// 1. Định nghĩa Interface Props
export interface RoleProps {
  id?: number;
  name: string;
  description?: string;
  isActive?: boolean;
  isSystem?: boolean;
  permissions?: Permission[]; // Có thể để optional và gán [] ở constructor
  createdAt?: Date;
  updatedAt?: Date;
}

export class Role {
  public readonly id?: number;
  public readonly name: string;
  public readonly description?: string;
  public readonly isActive: boolean;
  public readonly isSystem: boolean;
  public permissions: Permission[]; // Giữ public hoặc dùng getter để logic bên ngoài thao tác
  public readonly createdAt?: Date;
  public readonly updatedAt?: Date;

  // 2. Constructor nhận duy nhất 1 Object
  constructor(props: RoleProps) {
    this.id = props.id;
    this.name = props.name;
    this.description = props.description;
    this.isActive = props.isActive ?? true;
    this.isSystem = props.isSystem ?? false;
    this.permissions = props.permissions || []; // Mặc định mảng rỗng
    this.createdAt = props.createdAt;
    this.updatedAt = props.updatedAt;
  }

  // --- Domain Behaviors (Giữ nguyên logic) ---
  hasPermission(permissionName: string): boolean {
    return this.permissions.some((p) => p.name === permissionName);
  }

  addPermission(permission: Permission): void {
    if (!this.hasPermission(permission.name)) {
      this.permissions.push(permission);
    }
  }
}

