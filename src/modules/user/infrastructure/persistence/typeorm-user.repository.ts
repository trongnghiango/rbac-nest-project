import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { User } from '../../domain/entities/user.entity';
import { User as UserEntity } from '../../domain/entities/user.entity';

@Injectable()
export class TypeOrmUserRepository implements IUserRepository {
  constructor(
    @InjectRepository(UserEntity)
    private repository: Repository<UserEntity>,
  ) {}

  async findById(id: number): Promise<User | null> {
    const entity = await this.repository.findOne({ where: { id } });
    return entity ? this.toDomain(entity) : null;
  }

  async findByUsername(username: string): Promise<User | null> {
    const entity = await this.repository.findOne({ where: { username } });
    return entity ? this.toDomain(entity) : null;
  }

  async findByEmail(email: string): Promise<User | null> {
    const entity = await this.repository.findOne({ where: { email } });
    return entity ? this.toDomain(entity) : null;
  }

  async findAllActive(): Promise<User[]> {
    const entities = await this.repository.find({
      where: { isActive: true },
      order: { createdAt: 'DESC' },
    });
    return entities.map((entity) => this.toDomain(entity));
  }

  async save(user: User): Promise<User> {
    const entity = this.toPersistence(user);
    const saved = await this.repository.save(entity);
    return this.toDomain(saved);
  }

  async update(id: number, data: Partial<User>): Promise<User> {
    await this.repository.update(id, this.toPersistence(data as User));
    const updated = await this.repository.findOne({ where: { id } });
    return this.toDomain(updated!);
  }

  async delete(id: number): Promise<void> {
    await this.repository.delete(id);
  }

  async count(): Promise<number> {
    return this.repository.count();
  }

  private toDomain(entity: UserEntity): User {
    const user = new User();
    Object.assign(user, entity);
    return user;
  }

  private toPersistence(domain: User): Partial<UserEntity> {
    const {
      id,
      username,
      email,
      hashedPassword,
      fullName,
      isActive,
      profile,
      createdAt,
      updatedAt,
    } = domain;
    return {
      id,
      username,
      email,
      hashedPassword,
      fullName,
      isActive,
      profile,
      createdAt,
      updatedAt,
    };
  }
}
