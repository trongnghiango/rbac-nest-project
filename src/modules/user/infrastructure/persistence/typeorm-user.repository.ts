import { Injectable, NotFoundException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { User } from '../../domain/entities/user.entity';
import { UserOrmEntity } from './entities/user.orm-entity';
import { UserMapper } from './mappers/user.mapper';
import { AbstractTypeOrmRepository } from '../../../../core/shared/infrastructure/persistence/abstract-typeorm.repository';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable() // 👈 Kế thừa logic getRepository
export class TypeOrmUserRepository
  extends AbstractTypeOrmRepository<UserOrmEntity>
  implements IUserRepository
{
  constructor(
    @InjectRepository(UserOrmEntity)
    repository: Repository<UserOrmEntity>,
  ) {
    super(repository); // 👈 Pass vào cha
  }

  // Không cần viết lại hàm getRepository() nữa!

  async findById(id: number, tx?: Transaction): Promise<User | null> {
    const repo = this.getRepository(tx); // ✅ Gọi từ cha
    const entity = await repo.findOne({ where: { id } });
    return UserMapper.toDomain(entity);
  }

  async findByUsername(
    username: string,
    tx?: Transaction,
  ): Promise<User | null> {
    const repo = this.getRepository(tx);
    const entity = await repo.findOne({ where: { username } });
    return UserMapper.toDomain(entity);
  }

  async findByEmail(email: string, tx?: Transaction): Promise<User | null> {
    const repo = this.getRepository(tx);
    const entity = await repo.findOne({ where: { email } });
    return UserMapper.toDomain(entity);
  }

  async findAllActive(): Promise<User[]> {
    // Với hàm này ko cần tx cũng được, dùng this.repository (của cha)
    const entities = await this.repository.find({
      where: { isActive: true },
      order: { createdAt: 'DESC' },
    });
    return entities
      .map((entity) => UserMapper.toDomain(entity))
      .filter((u): u is User => u !== null);
  }

  async findAll(criteria?: Partial<User>): Promise<User[]> {
    return this.findAllActive();
  }

  async save(user: User, tx?: Transaction): Promise<User> {
    const repo = this.getRepository(tx); // ✅ Support Transaction
    const ormEntity = UserMapper.toPersistence(user);
    const saved = await repo.save(ormEntity);
    return UserMapper.toDomain(saved)!;
  }

  async update(id: number, data: Partial<User>): Promise<User> {
    await this.repository.update(id, data as any);
    const updated = await this.findById(id);
    if (!updated) throw new NotFoundException('User not found');
    return updated;
  }

  async delete(id: number, tx?: Transaction): Promise<void> {
    const repo = this.getRepository(tx);
    await repo.delete(id);
  }

  async exists(id: number, tx?: Transaction): Promise<boolean> {
    const user = await this.findById(id, tx);
    return !!user;
  }

  async count(): Promise<number> {
    return this.repository.count();
  }
}
