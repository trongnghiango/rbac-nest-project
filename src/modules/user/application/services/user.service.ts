import {
  Injectable,
  Inject,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
// FIX IMPORT: Import cả Token và Interface
import { IUserRepository } from '../../domain/repositories/user.repository';
import { PasswordUtil } from '../../../shared/utils/password.util';
import { User } from '../../domain/entities/user.entity';

@Injectable()
export class UserService {
  constructor(
    // FIX INJECT: Dùng Symbol IUserRepository
    @Inject(IUserRepository) private userRepository: IUserRepository,
  ) {}

  async createUser(data: any): Promise<any> {
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
      true,
      undefined,
      undefined,
      undefined,
      new Date(),
      new Date(),
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
    profileData: any,
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
