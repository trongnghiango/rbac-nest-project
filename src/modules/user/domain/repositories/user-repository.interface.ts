import { IRepository } from '../../../../core/shared/application/ports/repository.port';
import { User } from '../entities/user.entity';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

export interface IUserRepository extends IRepository<User, number> {
  findByUsername(username: string, tx?: Transaction): Promise<User | null>;
  findByEmail(email: string, tx?: Transaction): Promise<User | null>;
  // Overwrite save to return User (Abstract return void, but we need ID back)
  save(user: User, tx?: Transaction): Promise<User>;
}
