import {
  Entity,
  Column,
  PrimaryColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import type { UserProfile } from '../../../domain/types/user-profile.type';

@Entity('users')
export class UserOrmEntity {
  @PrimaryColumn('bigint')
  id: number;

  @Column({ unique: true })
  username: string;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', unique: true, nullable: true })
  email: string | null;

  @Column({ type: 'varchar', nullable: true })
  hashedPassword: string | null;

  @Column({ type: 'varchar', nullable: true })
  fullName: string | null;

  @Column({ default: true })
  isActive: boolean;

  @Column({ type: 'varchar', nullable: true })
  phoneNumber: string | null;

  @Column({ type: 'varchar', nullable: true })
  avatarUrl: string | null;

  @Column({ type: 'jsonb', nullable: true })
  profile: UserProfile | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
