import {
  Entity,
  Column,
  PrimaryColumn,
  CreateDateColumn,
  Index,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { Role } from './role.entity';

@Entity('user_roles')
@Index('idx_user_roles_user_id', ['userId'])
@Index('idx_user_roles_role_id', ['roleId'])
export class UserRole {
  @PrimaryColumn('bigint')
  userId: number;

  @PrimaryColumn('int')
  roleId: number;

  @Column('bigint', { nullable: true })
  assignedBy: number;

  @Column({ type: 'timestamptz', nullable: true })
  expiresAt: Date;

  @CreateDateColumn()
  assignedAt: Date;

  // Added relation for joins
  @ManyToOne(() => Role)
  @JoinColumn({ name: 'roleId' })
  role: Role;

  isActive(): boolean {
    if (!this.expiresAt) return true;
    return new Date() < this.expiresAt;
  }
}
