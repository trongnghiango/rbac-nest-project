import { Role } from '../entities/role.entity';
import { Permission } from '../entities/permission.entity';
import { UserRole } from '../entities/user-role.entity';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

export interface IRoleRepository {
  findByName(name: string, tx?: Transaction): Promise<Role | null>;
  save(role: Role, tx?: Transaction): Promise<Role>;
  findAllWithPermissions(roleIds: number[], tx?: Transaction): Promise<Role[]>;
  findAll(tx?: Transaction): Promise<Role[]>;
}

export interface IPermissionRepository {
  findByName(name: string, tx?: Transaction): Promise<Permission | null>;
  save(permission: Permission, tx?: Transaction): Promise<Permission>;
  findAll(tx?: Transaction): Promise<Permission[]>;
}

export interface IUserRoleRepository {
  findByUserId(userId: number, tx?: Transaction): Promise<UserRole[]>;
  save(userRole: UserRole, tx?: Transaction): Promise<void>;
  findOne(userId: number, roleId: number, tx?: Transaction): Promise<UserRole | null>;
  delete(userId: number, roleId: number, tx?: Transaction): Promise<void>;
}
