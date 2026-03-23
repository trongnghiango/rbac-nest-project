import { Role } from './role.entity';

// 1. Định nghĩa Interface cho Props
export interface UserRoleProps {
  userId: number;
  roleId: number;
  assignedBy?: number;
  expiresAt?: Date;
  assignedAt?: Date;
  role?: Role;
}

export class UserRole {
  // Định nghĩa các thuộc tính công khai (hoặc dùng getter/setter nếu muốn đóng gói kỹ hơn)
  public readonly userId: number;
  public readonly roleId: number;
  public readonly assignedBy?: number;
  public readonly expiresAt?: Date;
  public readonly assignedAt?: Date;
  public readonly role?: Role;

  // 2. Constructor nhận duy nhất 1 Object
  constructor(props: UserRoleProps) {
    this.userId = props.userId;
    this.roleId = props.roleId;
    this.assignedBy = props.assignedBy;
    this.expiresAt = props.expiresAt;
    this.assignedAt = props.assignedAt || new Date(); // Gán mặc định nếu không có
    this.role = props.role;
  }

  isActive(): boolean {
    if (!this.expiresAt) return true;
    return new Date() < this.expiresAt;
  }
}
