import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In, EntityManager, ObjectLiteral } from 'typeorm';
import { IRoleRepository, IPermissionRepository, IUserRoleRepository } from '../../../domain/repositories/rbac-repository.interface';
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';
import { RoleOrmEntity } from '../entities/role.orm-entity';
import { PermissionOrmEntity } from '../entities/permission.orm-entity';
import { UserRoleOrmEntity } from '../entities/user-role.orm-entity';
import { RbacMapper } from '../mappers/rbac.mapper';
// FIX PATH: Corrected to 5 levels up (../../../../../)
import { Transaction } from '../../../../../core/shared/application/ports/transaction-manager.port';

function getRepo<T extends ObjectLiteral>(baseRepo: Repository<T>, tx?: Transaction): Repository<T> {
    if (tx) {
        return (tx as EntityManager).getRepository(baseRepo.target) as Repository<T>;
    }
    return baseRepo;
}

@Injectable()
export class TypeOrmRoleRepository implements IRoleRepository {
  constructor(@InjectRepository(RoleOrmEntity) private repo: Repository<RoleOrmEntity>) {}

  async findByName(name: string, tx?: Transaction): Promise<Role | null> {
    const r = getRepo(this.repo, tx);
    const entity = await r.findOne({ where: { name }, relations: ['permissions'] });
    return RbacMapper.toRoleDomain(entity);
  }

  async save(role: Role, tx?: Transaction): Promise<Role> {
    const r = getRepo(this.repo, tx);
    const orm = RbacMapper.toRolePersistence(role);
    const saved = await r.save(orm);
    return RbacMapper.toRoleDomain(saved)!;
  }

  async findAllWithPermissions(roleIds: number[], tx?: Transaction): Promise<Role[]> {
    const r = getRepo(this.repo, tx);
    const entities = await r.find({
      where: { id: In(roleIds), isActive: true },
      relations: ['permissions']
    });
    return entities.map(e => RbacMapper.toRoleDomain(e)!);
  }

  async findAll(tx?: Transaction): Promise<Role[]> {
    const r = getRepo(this.repo, tx);
    const entities = await r.find({ relations: ['permissions'] });
    return entities.map(e => RbacMapper.toRoleDomain(e)!);
  }
}

@Injectable()
export class TypeOrmPermissionRepository implements IPermissionRepository {
  constructor(@InjectRepository(PermissionOrmEntity) private repo: Repository<PermissionOrmEntity>) {}

  async findByName(name: string, tx?: Transaction): Promise<Permission | null> {
    const r = getRepo(this.repo, tx);
    const entity = await r.findOne({ where: { name } });
    return RbacMapper.toPermissionDomain(entity);
  }

  async save(permission: Permission, tx?: Transaction): Promise<Permission> {
    const r = getRepo(this.repo, tx);
    const orm = RbacMapper.toPermissionPersistence(permission);
    const saved = await r.save(orm);
    return RbacMapper.toPermissionDomain(saved)!;
  }

  async findAll(tx?: Transaction): Promise<Permission[]> {
    const r = getRepo(this.repo, tx);
    const entities = await r.find();
    return entities.map(e => RbacMapper.toPermissionDomain(e)!);
  }
}

@Injectable()
export class TypeOrmUserRoleRepository implements IUserRoleRepository {
  constructor(@InjectRepository(UserRoleOrmEntity) private repo: Repository<UserRoleOrmEntity>) {}

  async findByUserId(userId: number, tx?: Transaction): Promise<UserRole[]> {
    const r = getRepo(this.repo, tx);
    const entities = await r.find({ where: { userId }, relations: ['role'] });
    return entities.map(e => RbacMapper.toUserRoleDomain(e)!);
  }

  async save(userRole: UserRole, tx?: Transaction): Promise<void> {
    const r = getRepo(this.repo, tx);
    const orm = RbacMapper.toUserRolePersistence(userRole);
    await r.save(orm);
  }

  async findOne(userId: number, roleId: number, tx?: Transaction): Promise<UserRole | null> {
    const r = getRepo(this.repo, tx);
    const entity = await r.findOne({ where: { userId, roleId } });
    return RbacMapper.toUserRoleDomain(entity);
  }

  async delete(userId: number, roleId: number, tx?: Transaction): Promise<void> {
    const r = getRepo(this.repo, tx);
    await r.delete({ userId, roleId });
  }
}
