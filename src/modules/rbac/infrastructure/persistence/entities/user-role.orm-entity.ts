import {
  Entity,
  Column,
  PrimaryColumn,
  CreateDateColumn,
  Index,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { RoleOrmEntity } from './role.orm-entity';

@Entity('user_roles')
@Index('idx_user_roles_user_id', ['userId'])
@Index('idx_user_roles_role_id', ['roleId'])
export class UserRoleOrmEntity {
  @PrimaryColumn('bigint')
  userId: number;

  @PrimaryColumn('int')
  roleId: number;

  // FIX: Thêm type: 'bigint'
  @Column({ type: 'bigint', nullable: true })
  assignedBy: number | null;

  // FIX: Thêm type: 'timestamptz'
  @Column({ type: 'timestamptz', nullable: true })
  expiresAt: Date | null;

  @CreateDateColumn()
  assignedAt: Date;

  @ManyToOne(() => RoleOrmEntity)
  @JoinColumn({ name: 'roleId' })
  role: RoleOrmEntity;
}
