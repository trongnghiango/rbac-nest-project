import { Role } from '../entities/role.entity';
import { Permission } from '../entities/permission.entity';
import { UserRole } from '../entities/user-role.entity';

// 1. Role Repository
export const IRoleRepository = Symbol('IRoleRepository');
export interface IRoleRepository {
  findByName(name: string): Promise<Role | null>;
  save(role: Role): Promise<Role>;
  findAllWithPermissions(roleIds: number[]): Promise<Role[]>;
  findAll(): Promise<Role[]>;

  // ✅ THÊM MỚI
  findInNames(names: string[]): Promise<Role[]>;
}

// 2. Permission Repository
export const IPermissionRepository = Symbol('IPermissionRepository');
export interface IPermissionRepository {
  findByName(name: string): Promise<Permission | null>;
  save(permission: Permission): Promise<Permission>;
  findAll(): Promise<Permission[]>;
}

// 3. User Role Repository
export const IUserRoleRepository = Symbol('IUserRoleRepository');
export interface IUserRoleRepository {
  findByUserId(userId: number): Promise<UserRole[]>;
  save(userRole: UserRole): Promise<void>;
  findOne(
    userId: number,
    roleId: number,
  ): Promise<UserRole | null>;
  delete(userId: number, roleId: number): Promise<void>;

  // ✅ THÊM MỚI
  saveMany(userRoles: UserRole[]): Promise<void>;
}
