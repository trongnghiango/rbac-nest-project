import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';

@Entity('sessions')
@Index('idx_sessions_user_id', ['userId'])
export class SessionOrmEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('bigint')
  userId: number;

  @Column({ type: 'varchar' })
  token: string;

  @Column({ type: 'timestamptz' })
  expiresAt: Date;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', nullable: true })
  ipAddress: string | null;

  @Column({ type: 'varchar', nullable: true })
  userAgent: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
