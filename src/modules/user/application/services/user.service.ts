import {
  Injectable,
  Inject,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { IUserRepository } from '../../domain/repositories/user.repository';
import { PasswordUtil } from '@core/shared/utils/password.util';
import { User } from '../../domain/entities/user.entity';
import { UserProfile } from '../../domain/types/user-profile.type';

export interface CreateUserParams {
  id: number | string;
  username: string;
  email?: string;
  password?: string;
  fullName: string;
}

@Injectable()
export class UserService {
  constructor(
    @Inject(IUserRepository) private userRepository: IUserRepository,
  ) { }

  async createUser(
    data: CreateUserParams,
  ): Promise<User> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) throw new BadRequestException('User already exists');

    let hashedPassword;
    if (data.password) {
      if (!PasswordUtil.validateStrength(data.password))
        throw new BadRequestException('Weak password');
      hashedPassword = await PasswordUtil.hash(data.password);
    }

    const newUser = new User({
      username: data.username,
      email: data.email,
      hashedPassword: hashedPassword,
      personalInfo: {
        fullName: data.fullName
      },
      isActive: true,
      roles: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const user = await this.userRepository.save(newUser);
    return user;
  }

  async validateCredentials(
    username: string,
    pass: string,
  ): Promise<User | null> {
    const user = await this.userRepository.findByUsername(username);
    if (!user || !user.isActive || !user.hashedPassword) return null;
    const isValid = await PasswordUtil.compare(pass, user.hashedPassword);
    return isValid ? user : null;
  }

  async getUserById(id: number): Promise<User> {
    const user = await this.userRepository.findById(id);
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async updateUserProfile(
    userId: number,
    profileData: UserProfile,
  ): Promise<User> {
    const user = await this.userRepository.findById(userId);
    if (!user) throw new NotFoundException('User not found');

    user.updatePersonalInfo(profileData);
    const updated = await this.userRepository.save(user);
    return updated;
  }

  async deactivateUser(userId: number): Promise<void> {
    const user = await this.userRepository.findById(userId);
    if (!user) throw new NotFoundException('User not found');
    user.deactivate();
    await this.userRepository.save(user);
  }
}
