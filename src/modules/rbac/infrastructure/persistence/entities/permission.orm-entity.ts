import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';

@Entity('permissions')
export class PermissionOrmEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true, length: 100 })
  name: string;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', nullable: true })
  description: string | null;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', length: 50, nullable: true })
  resourceType: string | null;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', length: 50, nullable: true })
  action: string | null;

  @Column({ default: '*' })
  attributes: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;
}
