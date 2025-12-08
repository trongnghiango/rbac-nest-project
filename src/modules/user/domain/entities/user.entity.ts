import {
  Entity,
  Column,
  PrimaryColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import type { UserProfile } from '../types/user-profile.type';

@Entity('users')
export class User {
  @PrimaryColumn('bigint')
  id: number; // Telegram ID or custom ID

  @Column({ unique: true })
  username: string;

  @Column({ unique: true, nullable: true })
  email?: string;

  @Column({ nullable: true })
  hashedPassword?: string;

  @Column()
  fullName: string;

  @Column({ default: true })
  isActive: boolean;

  @Column({ nullable: true })
  phoneNumber?: string;

  @Column({ nullable: true })
  avatarUrl?: string;

  @Column({ type: 'jsonb', nullable: true }) // Đổi simple-json -> jsonb (Postgres only)
  profile?: UserProfile;
  // @Column('simple-json', { nullable: true })
  // profile?: any;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Domain methods
  updateProfile(profileData: UserProfile): void {
    this.profile = { ...this.profile, ...profileData };
    this.updatedAt = new Date();
  }

  setPassword(password: string): void {
    // Password hashing should be done in application service
    this.hashedPassword = password; // Will be hashed by service
    this.updatedAt = new Date();
  }

  deactivate(): void {
    this.isActive = false;
    this.updatedAt = new Date();
  }

  activate(): void {
    this.isActive = true;
    this.updatedAt = new Date();
  }

  toJSON() {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { hashedPassword, ...rest } = this;
    return rest;
  }
}
