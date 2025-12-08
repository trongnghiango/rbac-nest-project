import { Injectable, Inject } from '@nestjs/common';
import type { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { PasswordUtil } from '../../../shared/utils/password.util';
import { User } from '../../domain/entities/user.entity';

@Injectable()
export class UserService {
  constructor(
    @Inject('IUserRepository') private userRepository: IUserRepository,
  ) {}

  async createUser(data: {
    id: number;
    username: string;
    email?: string;
    password?: string;
    fullName: string;
  }): Promise<any> {
    // Check if user exists
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) {
      throw new Error('User already exists');
    }

    // Hash password if provided
    let hashedPassword: string | undefined;
    if (data.password) {
      if (!PasswordUtil.validateStrength(data.password)) {
        throw new Error('Password does not meet strength requirements');
      }
      hashedPassword = await PasswordUtil.hash(data.password);
    }

    // Cast object to User to match repository interface
    const newUser = new User();
    newUser.id = data.id;
    newUser.username = data.username;
    newUser.email = data.email;
    newUser.hashedPassword = hashedPassword;
    newUser.fullName = data.fullName;
    newUser.isActive = true;
    newUser.createdAt = new Date();
    newUser.updatedAt = new Date();

    const user = await this.userRepository.save(newUser);

    return user.toJSON();
  }

  async validateCredentials(
    username: string,
    password: string,
  ): Promise<User | null> {
    const user = await this.userRepository.findByUsername(username);
    if (!user || !user.isActive || !user.hashedPassword) {
      return null;
    }

    const isValid = await PasswordUtil.compare(password, user.hashedPassword);
    return isValid ? user : null;
  }

  async getUserById(id: number): Promise<ReturnType<User['toJSON']>> {
    const user = await this.userRepository.findById(id);
    if (!user) {
      throw new Error('User not found');
    }
    return user.toJSON();
  }

  async updateUserProfile(
    userId: number,
    profileData: any,
  ): Promise<ReturnType<User['toJSON']>> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    user.updateProfile(profileData);
    const updated = await this.userRepository.save(user);
    return updated.toJSON();
  }

  async deactivateUser(userId: number): Promise<void> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    user.deactivate();
    await this.userRepository.save(user);
  }
}
