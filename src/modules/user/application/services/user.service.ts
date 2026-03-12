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
  id: number;
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
  ): Promise<ReturnType<User['toJSON']>> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) throw new BadRequestException('User already exists');

    let hashedPassword;
    if (data.password) {
      if (!PasswordUtil.validateStrength(data.password))
        throw new BadRequestException('Weak password');
      hashedPassword = await PasswordUtil.hash(data.password);
    }

    const newUser = new User(
      data.id,
      data.username,
      data.email,
      hashedPassword,
      data.fullName,
      true,       // isActive
      [],         // roles (Mặc định rỗng, gán role sau)
      undefined,  // telegramId
      undefined,  // phoneNumber
      undefined,  // avatarUrl
      undefined,  // profile
      new Date(), // createdAt
      new Date(), // updatedAt 
    );

    const user = await this.userRepository.save(newUser);
    return user.toJSON();
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

  async getUserById(id: number): Promise<ReturnType<User['toJSON']>> {
    const user = await this.userRepository.findById(id);
    if (!user) throw new NotFoundException('User not found');
    return user.toJSON();
  }

  async updateUserProfile(
    userId: number,
    profileData: UserProfile,
  ): Promise<ReturnType<User['toJSON']>> {
    const user = await this.userRepository.findById(userId);
    if (!user) throw new NotFoundException('User not found');

    user.updateProfile(profileData);
    const updated = await this.userRepository.save(user);
    return updated.toJSON();
  }

  async deactivateUser(userId: number): Promise<void> {
    const user = await this.userRepository.findById(userId);
    if (!user) throw new NotFoundException('User not found');
    user.deactivate();
    await this.userRepository.save(user);
  }
}
