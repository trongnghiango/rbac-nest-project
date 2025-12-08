import { Repository } from 'typeorm';
import { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { User } from '../../domain/entities/user.entity';
import { User as UserEntity } from '../../domain/entities/user.entity';
export declare class TypeOrmUserRepository implements IUserRepository {
    private repository;
    constructor(repository: Repository<UserEntity>);
    findById(id: number): Promise<User | null>;
    findByUsername(username: string): Promise<User | null>;
    findByEmail(email: string): Promise<User | null>;
    findAllActive(): Promise<User[]>;
    save(user: User): Promise<User>;
    update(id: number, data: Partial<User>): Promise<User>;
    delete(id: number): Promise<void>;
    count(): Promise<number>;
    private toDomain;
    private toPersistence;
}
