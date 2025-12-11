import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { ISessionRepository } from '../../domain/repositories/session-repository.interface';
import { Session } from '../../domain/entities/session.entity';
import { SessionOrmEntity } from './entities/session.orm-entity';
import { SessionMapper } from './mappers/session.mapper';
import { AbstractTypeOrmRepository } from '../../../../core/shared/infrastructure/persistence/abstract-typeorm.repository';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable() // 👈 Kế thừa
export class TypeOrmSessionRepository
  extends AbstractTypeOrmRepository<SessionOrmEntity>
  implements ISessionRepository
{
  constructor(
    @InjectRepository(SessionOrmEntity)
    repository: Repository<SessionOrmEntity>,
  ) {
    super(repository);
  }

  async create(session: Session, tx?: Transaction): Promise<void> {
    const repo = this.getRepository(tx); // ✅ Gọi từ cha
    const orm = SessionMapper.toPersistence(session);
    await repo.save(orm);
  }

  async findByUserId(userId: number): Promise<Session[]> {
    const orms = await this.repository.find({ where: { userId } });
    return orms
      .map(SessionMapper.toDomain)
      .filter((s): s is Session => s !== null);
  }

  async deleteByUserId(userId: number): Promise<void> {
    await this.repository.delete({ userId });
  }
}
