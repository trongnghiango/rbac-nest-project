## File: src/bootstrap/app.module.ts
```
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';

import databaseConfig from '../config/database.config';
import appConfig from '../config/app.config';
import loggingConfig from '../config/logging.config';

import { CoreModule } from '../core/core.module';
import { SharedModule } from '../modules/shared/shared.module';
import { UserModule } from '../modules/user/user.module';
import { AuthModule } from '../modules/auth/auth.module';
import { RbacModule } from '../modules/rbac/rbac.module';
import { TestModule } from '../modules/test/test.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      load: [databaseConfig, appConfig, loggingConfig],
    }),
    CoreModule,
    SharedModule,
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => {
        const dbConfig = config.get('database');
        return {
          ...dbConfig,
          // Load cả Entities và Migrations
          entities: [__dirname + '/../**/*.orm-entity{.ts,.js}'],
        };
      },
      inject: [ConfigService],
    }),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: () => ({ ttl: 300, max: 100 }),
      inject: [ConfigService],
    }),
    UserModule,
    AuthModule,
    RbacModule,
    TestModule,
  ],
})
export class AppModule {}
```

## File: src/bootstrap/main.ts
```
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService);

  const prefix: string = config.get('app.apiPrefix', 'api');
  app.setGlobalPrefix(prefix);

  app.enableCors();

  // --- SWAGGER CONFIGURATION ---
  const swaggerConfig = new DocumentBuilder()
    .setTitle('RBAC System API')
    .setDescription('The RBAC System API description')
    .setVersion('1.0')
    .addBearerAuth() // Thêm nút "Authorize" để nhập Token
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  // Đường dẫn tài liệu: /docs
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true, // Giữ token khi refresh trang
    },
  });
  // -----------------------------

  const port: number = config.get('app.port', 3000);
  await app.listen(port);

  console.log(`🚀 API is running on: http://localhost:${port}/${prefix}`);
  console.log(`📚 Swagger Docs:      http://localhost:${port}/docs`);
  console.log(
    `📊 Health check:      http://localhost:${port}/${prefix}/test/health`,
  );
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
bootstrap().catch((err) => console.error('Err::', err['message']));
```

## File: src/modules/auth/domain/entities/session.entity.ts
```
export class Session {
  constructor(
    public id: string | undefined, // Cho phép undefined
    public userId: number,
    public token: string,
    public expiresAt: Date,
    public ipAddress?: string,
    public userAgent?: string,
    public createdAt?: Date,
  ) {}

  isExpired(): boolean {
    return new Date() > this.expiresAt;
  }
}
```

## File: src/modules/auth/domain/repositories/session-repository.interface.ts
```
import { Session } from '../entities/session.entity';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

export interface ISessionRepository {
  create(session: Session, tx?: Transaction): Promise<void>;
  findByUserId(userId: number): Promise<Session[]>;
  deleteByUserId(userId: number): Promise<void>;
}
```

## File: src/modules/auth/application/services/authentication.service.ts
```
import {
  Injectable,
  Inject,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import type { ISessionRepository } from '../../domain/repositories/session-repository.interface';
import { PasswordUtil } from '../../../shared/utils/password.util';
import { User } from '../../../user/domain/entities/user.entity';
import { Session } from '../../domain/entities/session.entity';
import { JwtPayload } from '../../../shared/types/common.types';
import type { ITransactionManager } from '../../../../core/shared/application/ports/transaction-manager.port'; // FIX: import type

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject('IUserRepository') private userRepository: IUserRepository,
    @Inject('ISessionRepository') private sessionRepository: ISessionRepository,
    @Inject('ITransactionManager') private txManager: ITransactionManager,
    private jwtService: JwtService,
  ) {}

  async login(credentials: {
    username: string;
    password: string;
    ip?: string;
    userAgent?: string;
  }): Promise<any> {
    const user = await this.userRepository.findByUsername(credentials.username);

    if (!user || !user.isActive)
      throw new UnauthorizedException('Invalid credentials');
    // Access getter directly (domain encapsulation)
    if (!user.hashedPassword)
      throw new UnauthorizedException('Password not set');

    const isValid = await PasswordUtil.compare(
      credentials.password,
      user.hashedPassword,
    );
    if (!isValid) throw new UnauthorizedException('Invalid credentials');

    if (!user.id) throw new InternalServerErrorException('User ID is missing');

    const payload: JwtPayload = {
      sub: user.id,
      username: user.username,
      roles: [],
    };
    const accessToken = this.jwtService.sign(payload);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 1);

    const session = new Session(
      undefined,
      user.id,
      accessToken,
      expiresAt,
      credentials.ip,
      credentials.userAgent,
      new Date(),
    );

    await this.sessionRepository.create(session);

    return {
      accessToken,
      user: user.toJSON(),
    };
  }

  async validateUser(
    payload: JwtPayload,
  ): Promise<ReturnType<User['toJSON']> | null> {
    const user = await this.userRepository.findById(payload.sub);
    if (!user || !user.isActive) return null;
    return user.toJSON();
  }

  async register(data: any): Promise<any> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) throw new BadRequestException('User already exists');

    const hashedPassword = await PasswordUtil.hash(data.password);

    const newUser = new User(
      undefined,
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

    return this.txManager.runInTransaction(async (tx) => {
      const savedUser = await this.userRepository.save(newUser, tx);
      if (!savedUser.id)
        throw new InternalServerErrorException('Failed to generate User ID');

      const payload: JwtPayload = {
        sub: savedUser.id,
        username: savedUser.username,
        roles: [],
      };
      const accessToken = this.jwtService.sign(payload);

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 1);

      const session = new Session(
        undefined,
        savedUser.id,
        accessToken,
        expiresAt,
        undefined,
        undefined,
        new Date(),
      );

      await this.sessionRepository.create(session, tx);

      return { accessToken, user: savedUser.toJSON() };
    });
  }
}
```

## File: src/modules/auth/infrastructure/controllers/auth.controller.ts
```
import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Req,
  Ip,
} from '@nestjs/common';
import { AuthenticationService } from '../../application/services/authentication.service';
import { Public } from '../decorators/public.decorator';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { User } from '../../../user/domain/entities/user.entity';
import { LoginDto, RegisterDto } from '../dtos/auth.dto';
import type { Request } from 'express'; // Import Request

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthenticationService) {}

  @Public()
  @Post('login')
  async login(
    @Body() credentials: LoginDto,
    @Ip() ip: string,
    @Req() request: Request, // Lấy User Agent từ Request
  ) {
    return this.authService.login({
      ...credentials,
      ip: ip,
      userAgent: request.headers['user-agent'],
    });
  }

  @Public()
  @Post('register')
  async register(@Body() data: RegisterDto) {
    return this.authService.register(data);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@CurrentUser() user: User) {
    return { user: user.toJSON() };
  }
}
```

## File: src/modules/auth/infrastructure/guards/jwt-auth.guard.ts
```
import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    return super.canActivate(context);
  }
}
```

## File: src/modules/auth/infrastructure/decorators/current-user.decorator.ts
```
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from '../../../user/domain/entities/user.entity';

export const CurrentUser = createParamDecorator(
  // 1. Thêm dấu _ trước data để báo cho TS biết biến này "cố tình" không dùng
  (_data: unknown, ctx: ExecutionContext) => {
    // 2. Ép kiểu Generic cho getRequest để TS biết request này là Object, không phải 'any'
    // { user: any } nghĩa là: Tao cam kết request này có thuộc tính user
    const request = ctx.switchToHttp().getRequest<{ user: User }>();

    return request.user;
  },
);

// export const CurrentUserOld = createParamDecorator(
//   (data: unknown, ctx: ExecutionContext) => {
//     const request = ctx.switchToHttp().getRequest();
//     return request.user;
//   },
// );
```

## File: src/modules/auth/infrastructure/decorators/public.decorator.ts
```
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

## File: src/modules/auth/infrastructure/strategies/jwt.strategy.ts
```
import { Injectable, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import { JwtPayload } from '../../../shared/types/common.types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    @Inject('IUserRepository') private userRepository: IUserRepository,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET') || 'super-secret-key',
    });
  }

  async validate(payload: JwtPayload) {
    const user = await this.userRepository.findById(payload.sub);
    if (!user || !user.isActive) {
      return null;
    }

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      roles: payload.roles || [],
    };
  }
}
```

## File: src/modules/auth/infrastructure/dtos/auth.dto.ts
```
import {
  IsString,
  MinLength,
  IsNumber,
  IsOptional,
  IsEmail,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'superadmin', description: 'Username for login' })
  @IsString()
  username: string;

  @ApiProperty({
    example: 'SuperAdmin123!',
    description: 'Password (min 6 chars)',
  })
  @IsString()
  @MinLength(6)
  password: string;
}

export class RegisterDto {
  @ApiProperty({ example: 12345, description: 'User ID (BigInt)' })
  @IsNumber()
  id: number;

  @ApiProperty({ example: 'newuser', description: 'Unique username' })
  @IsString()
  username: string;

  @ApiProperty({ example: 'StrongP@ss1', description: 'Strong password' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'Nguyen Van A', description: 'Full Name' })
  @IsString()
  fullName: string;

  @ApiPropertyOptional({ example: 'user@example.com' })
  @IsOptional()
  @IsEmail()
  email?: string;
}
```

## File: src/modules/auth/infrastructure/persistence/entities/session.orm-entity.ts
```
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';

@Entity('sessions')
@Index('idx_sessions_user_id', ['userId'])
export class SessionOrmEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('bigint')
  userId: number;

  @Column({ type: 'varchar' })
  token: string;

  @Column({ type: 'timestamptz' })
  expiresAt: Date;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', nullable: true })
  ipAddress: string | null;

  @Column({ type: 'varchar', nullable: true })
  userAgent: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
```

## File: src/modules/auth/infrastructure/persistence/mappers/session.mapper.ts
```
import { Session } from '../../../domain/entities/session.entity';
import { SessionOrmEntity } from '../entities/session.orm-entity';

export class SessionMapper {
  static toDomain(orm: SessionOrmEntity | null): Session | null {
    if (!orm) return null;
    return new Session(
      orm.id,
      Number(orm.userId),
      orm.token,
      orm.expiresAt,
      orm.ipAddress || undefined, // Null -> Undefined
      orm.userAgent || undefined,
      orm.createdAt,
    );
  }

  static toPersistence(domain: Session): SessionOrmEntity {
    const orm = new SessionOrmEntity();
    if (domain.id) orm.id = domain.id;
    orm.userId = domain.userId;
    orm.token = domain.token;
    orm.expiresAt = domain.expiresAt;
    // FIX: Convert undefined -> null
    orm.ipAddress = domain.ipAddress || null;
    orm.userAgent = domain.userAgent || null;

    orm.createdAt = domain.createdAt || new Date();
    return orm;
  }
}
```

## File: src/modules/auth/infrastructure/persistence/typeorm-session.repository.ts
```
import { Injectable } from '@nestjs/common';
import { Repository, EntityManager } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { ISessionRepository } from '../../domain/repositories/session-repository.interface';
import { Session } from '../../domain/entities/session.entity';
import { SessionOrmEntity } from './entities/session.orm-entity';
import { SessionMapper } from './mappers/session.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class TypeOrmSessionRepository implements ISessionRepository {
  constructor(
    @InjectRepository(SessionOrmEntity)
    private readonly repository: Repository<SessionOrmEntity>,
  ) {}

  private getRepository(tx?: Transaction): Repository<SessionOrmEntity> {
    if (tx) {
      const entityManager = tx as EntityManager;
      return entityManager.getRepository(SessionOrmEntity);
    }
    return this.repository;
  }

  async create(session: Session, tx?: Transaction): Promise<void> {
    const repo = this.getRepository(tx);
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
```

## File: src/modules/auth/auth.module.ts
```
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';

import { UserModule } from '../user/user.module';
import { AuthenticationService } from './application/services/authentication.service';
import { JwtStrategy } from './infrastructure/strategies/jwt.strategy';
import { JwtAuthGuard } from './infrastructure/guards/jwt-auth.guard';
import { AuthController } from './infrastructure/controllers/auth.controller';
import { SessionOrmEntity } from './infrastructure/persistence/entities/session.orm-entity';
import { TypeOrmSessionRepository } from './infrastructure/persistence/typeorm-session.repository';

@Module({
  imports: [
    UserModule,
    TypeOrmModule.forFeature([SessionOrmEntity]),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET') || 'super-secret-key',
        signOptions: { expiresIn: configService.get('JWT_EXPIRES_IN', '24h') },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthenticationService,
    JwtStrategy,
    JwtAuthGuard,
    {
      provide: 'ISessionRepository',
      useClass: TypeOrmSessionRepository,
    },
  ],
  exports: [JwtAuthGuard, AuthenticationService, JwtModule, PassportModule],
})
export class AuthModule {}
```

## File: src/modules/user/domain/entities/user.entity.ts
```
import type { UserProfile } from '../types/user-profile.type';

export class User {
  // Properties are private (Encapsulation)
  constructor(
    private _id: number | undefined,
    private _username: string,
    private _email?: string,
    private _hashedPassword?: string,
    private _fullName?: string,
    private _isActive: boolean = true,
    private _phoneNumber?: string,
    private _avatarUrl?: string,
    private _profile?: UserProfile,
    private _createdAt?: Date,
    private _updatedAt?: Date,
  ) {}

  // Getters
  get id() {
    return this._id;
  }
  get username() {
    return this._username;
  }
  get email() {
    return this._email;
  }
  get hashedPassword() {
    return this._hashedPassword;
  }
  get fullName() {
    return this._fullName;
  }
  get isActive() {
    return this._isActive;
  }
  get phoneNumber() {
    return this._phoneNumber;
  }
  get avatarUrl() {
    return this._avatarUrl;
  }
  get profile() {
    return this._profile;
  }
  get createdAt() {
    return this._createdAt;
  }
  get updatedAt() {
    return this._updatedAt;
  }

  // Business Methods (Behavior)

  // Set ID (Only used by persistence layer when creating new)
  setId(id: number) {
    if (this._id) throw new Error('ID is immutable once set');
    this._id = id;
  }

  updateProfile(profileData: UserProfile): void {
    this._profile = { ...this._profile, ...profileData };
    this._updatedAt = new Date();
  }

  changePassword(hashedPassword: string): void {
    this._hashedPassword = hashedPassword;
    this._updatedAt = new Date();
  }

  deactivate(): void {
    this._isActive = false;
    this._updatedAt = new Date();
  }

  activate(): void {
    this._isActive = true;
    this._updatedAt = new Date();
  }

  toJSON() {
    return {
      id: this._id,
      username: this._username,
      email: this._email,
      fullName: this._fullName,
      isActive: this._isActive,
      phoneNumber: this._phoneNumber,
      avatarUrl: this._avatarUrl,
      profile: this._profile,
      createdAt: this._createdAt,
      updatedAt: this._updatedAt,
    };
  }
}
```

## File: src/modules/user/domain/repositories/user-repository.interface.ts
```
import { IRepository } from '../../../../core/shared/application/ports/repository.port';
import { User } from '../entities/user.entity';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

export interface IUserRepository extends IRepository<User, number> {
  findByUsername(username: string, tx?: Transaction): Promise<User | null>;
  findByEmail(email: string, tx?: Transaction): Promise<User | null>;
  // Overwrite save to return User (Abstract return void, but we need ID back)
  save(user: User, tx?: Transaction): Promise<User>;
}
```

## File: src/modules/user/domain/types/user-profile.type.ts
```
export interface UserProfile {
  bio?: string;
  birthday?: string;
  avatarUrl?: string;
  gender?: 'male' | 'female' | 'other';
  socialLinks?: {
    facebook?: string;
    telegram?: string;
    website?: string;
  };
  settings?: {
    theme: 'dark' | 'light';
    notifications: boolean;
  };
}
```

## File: src/modules/user/application/services/user.service.ts
```
import {
  Injectable,
  Inject,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
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
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) {
      throw new BadRequestException('User already exists');
    }

    let hashedPassword;
    if (data.password) {
      if (!PasswordUtil.validateStrength(data.password)) {
        throw new BadRequestException(
          'Password does not meet strength requirements',
        );
      }
      hashedPassword = await PasswordUtil.hash(data.password);
    }

    // FIX: Sử dụng Constructor chuẩn của Domain
    const newUser = new User(
      data.id,
      data.username,
      data.email,
      hashedPassword,
      data.fullName,
      true, // isActive
      undefined, // phoneNumber
      undefined, // avatarUrl
      undefined, // profile
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
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user.toJSON();
  }

  async updateUserProfile(
    userId: number,
    profileData: any,
  ): Promise<ReturnType<User['toJSON']>> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    user.updateProfile(profileData);
    const updated = await this.userRepository.save(user);
    return updated.toJSON();
  }

  async deactivateUser(userId: number): Promise<void> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    user.deactivate();
    await this.userRepository.save(user);
  }
}
```

## File: src/modules/user/infrastructure/persistence/typeorm-user.repository.ts
```
import { Injectable } from '@nestjs/common';
import { Repository, EntityManager } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { User } from '../../domain/entities/user.entity';
import { UserOrmEntity } from './entities/user.orm-entity';
import { UserMapper } from './mappers/user.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class TypeOrmUserRepository implements IUserRepository {
  constructor(
    @InjectRepository(UserOrmEntity)
    private readonly repository: Repository<UserOrmEntity>,
  ) {}

  // Helper để lấy đúng Repo (có Transaction hoặc không)
  private getRepository(tx?: Transaction): Repository<UserOrmEntity> {
    if (tx) {
      const entityManager = tx as EntityManager;
      return entityManager.getRepository(UserOrmEntity);
    }
    return this.repository;
  }

  async findById(id: number, tx?: Transaction): Promise<User | null> {
    const repo = this.getRepository(tx);
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
    const entities = await this.repository.find({
      where: { isActive: true },
      order: { createdAt: 'DESC' },
    });
    return entities
      .map((entity) => UserMapper.toDomain(entity))
      .filter((u): u is User => u !== null);
  }

  // Bắt buộc phải implement do IRepository yêu cầu
  async findAll(criteria?: Partial<User>): Promise<User[]> {
    // Basic implementation
    return this.findAllActive();
  }

  async save(user: User, tx?: Transaction): Promise<User> {
    const repo = this.getRepository(tx);
    const ormEntity = UserMapper.toPersistence(user);
    const saved = await repo.save(ormEntity);
    return UserMapper.toDomain(saved)!;
  }

  async update(id: number, data: Partial<User>): Promise<User> {
    await this.repository.update(id, data as any);
    const updated = await this.findById(id);
    if (!updated) throw new Error('User not found');
    return updated;
  }

  async delete(id: number): Promise<void> {
    await this.repository.delete(id);
  }

  async exists(id: number): Promise<boolean> {
    const user = await this.findById(id);
    return !!user;
  }

  async count(): Promise<number> {
    return this.repository.count();
  }
}
```

## File: src/modules/user/infrastructure/persistence/entities/user.orm-entity.ts
```
import {
  Entity,
  Column,
  PrimaryColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import type { UserProfile } from '../../../domain/types/user-profile.type';

@Entity('users')
export class UserOrmEntity {
  @PrimaryColumn('bigint')
  id: number;

  @Column({ unique: true })
  username: string;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', unique: true, nullable: true })
  email: string | null;

  @Column({ type: 'varchar', nullable: true })
  hashedPassword: string | null;

  @Column({ type: 'varchar', nullable: true })
  fullName: string | null;

  @Column({ default: true })
  isActive: boolean;

  @Column({ type: 'varchar', nullable: true })
  phoneNumber: string | null;

  @Column({ type: 'varchar', nullable: true })
  avatarUrl: string | null;

  @Column({ type: 'jsonb', nullable: true })
  profile: UserProfile | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

## File: src/modules/user/infrastructure/persistence/mappers/user.mapper.ts
```
import { User } from '../../../domain/entities/user.entity';
import { UserOrmEntity } from '../entities/user.orm-entity';

export class UserMapper {
  static toDomain(ormEntity: UserOrmEntity | null): User | null {
    if (!ormEntity) return null;

    return new User(
      Number(ormEntity.id),
      ormEntity.username,
      ormEntity.email || undefined,
      ormEntity.hashedPassword || undefined,
      ormEntity.fullName || undefined,
      ormEntity.isActive,
      ormEntity.phoneNumber || undefined,
      ormEntity.avatarUrl || undefined,
      ormEntity.profile || undefined,
      ormEntity.createdAt,
      ormEntity.updatedAt,
    );
  }

  static toPersistence(domainEntity: User): UserOrmEntity {
    const ormEntity = new UserOrmEntity();
    if (domainEntity.id !== undefined) {
      ormEntity.id = domainEntity.id;
    }
    ormEntity.username = domainEntity.username;
    ormEntity.email = domainEntity.email || null;
    ormEntity.hashedPassword = domainEntity.hashedPassword || null;
    ormEntity.fullName = domainEntity.fullName || null;
    ormEntity.isActive = domainEntity.isActive;
    ormEntity.phoneNumber = domainEntity.phoneNumber || null;
    ormEntity.avatarUrl = domainEntity.avatarUrl || null;
    ormEntity.profile = domainEntity.profile || null;

    ormEntity.createdAt = domainEntity.createdAt || new Date();
    ormEntity.updatedAt = domainEntity.updatedAt || new Date();
    return ormEntity;
  }
}
```

## File: src/modules/user/infrastructure/controllers/user.controller.ts
```
import {
  Controller,
  Get,
  Param,
  Put,
  Body,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import { UserService } from '../../application/services/user.service';
import { CurrentUser } from '../../../auth/infrastructure/decorators/current-user.decorator';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { User } from '../../domain/entities/user.entity';
import { UpdateProfileDto } from '../dtos/update-profile.dto';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UserController {
  constructor(private userService: UserService) {}

  @Get('profile')
  async getProfile(@CurrentUser() user: User) {
    // FIX: User từ Token chắc chắn phải có ID
    if (!user.id) throw new BadRequestException('Invalid User Context');
    return this.userService.getUserById(user.id);
  }

  @Put('profile')
  async updateProfile(
    @CurrentUser() user: User,
    @Body() profileData: UpdateProfileDto,
  ) {
    // FIX: User từ Token chắc chắn phải có ID
    if (!user.id) throw new BadRequestException('Invalid User Context');
    return this.userService.updateUserProfile(user.id, profileData);
  }

  @Get(':id')
  async getUserById(@Param('id') id: number) {
    return this.userService.getUserById(id);
  }
}
```

## File: src/modules/user/infrastructure/dtos/update-profile.dto.ts
```
import {
  IsString,
  IsOptional,
  IsUrl,
  IsEnum,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

class SocialLinksDto {
  @ApiPropertyOptional() @IsOptional() @IsUrl() facebook?: string;
  @ApiPropertyOptional() @IsOptional() @IsUrl() telegram?: string;
  @ApiPropertyOptional() @IsOptional() @IsUrl() website?: string;
}

class SettingsDto {
  @ApiPropertyOptional({ enum: ['dark', 'light'] })
  @IsOptional()
  @IsEnum(['dark', 'light'])
  theme: 'dark' | 'light';

  @ApiPropertyOptional()
  @IsOptional()
  notifications: boolean;
}

export class UpdateProfileDto {
  @ApiPropertyOptional({ example: 'I love coding' })
  @IsOptional()
  @IsString()
  bio?: string;

  @ApiPropertyOptional({ example: '1990-01-01' })
  @IsOptional()
  @IsString()
  birthday?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsUrl()
  avatarUrl?: string;

  @ApiPropertyOptional({ enum: ['male', 'female', 'other'] })
  @IsOptional()
  @IsEnum(['male', 'female', 'other'])
  gender?: 'male' | 'female' | 'other';

  @ApiPropertyOptional()
  @IsOptional()
  @ValidateNested()
  @Type(() => SocialLinksDto)
  socialLinks?: SocialLinksDto;

  @ApiPropertyOptional()
  @IsOptional()
  @ValidateNested()
  @Type(() => SettingsDto)
  settings?: SettingsDto;
}
```

## File: src/modules/user/user.module.ts
```
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserService } from './application/services/user.service';
import { TypeOrmUserRepository } from './infrastructure/persistence/typeorm-user.repository';
import { UserController } from './infrastructure/controllers/user.controller';
import { UserOrmEntity } from './infrastructure/persistence/entities/user.orm-entity';

@Module({
  imports: [TypeOrmModule.forFeature([UserOrmEntity])], // Import ORM Entity here, NOT Domain Entity
  controllers: [UserController],
  providers: [
    UserService,
    {
      provide: 'IUserRepository',
      useClass: TypeOrmUserRepository,
    },
  ],
  exports: [UserService, 'IUserRepository'],
})
export class UserModule {}
```

## File: src/modules/rbac/domain/entities/role.entity.ts
```
import { Permission } from './permission.entity';

export class Role {
  constructor(
    public id: number | undefined,
    public name: string,
    public description?: string,
    public isActive: boolean = true,
    public isSystem: boolean = false,
    public permissions: Permission[] = [],
    public createdAt?: Date,
    public updatedAt?: Date,
  ) {}

  hasPermission(permissionName: string): boolean {
    return this.permissions.some((p) => p.name === permissionName);
  }

  addPermission(permission: Permission): void {
    if (!this.hasPermission(permission.name)) {
      this.permissions.push(permission);
    }
  }
}
```

## File: src/modules/rbac/domain/entities/permission.entity.ts
```
export class Permission {
  constructor(
    public id: number | undefined,
    public name: string,
    public description?: string,
    public resourceType?: string,
    public action?: string,
    public isActive: boolean = true,
    public attributes: string = '*',
    public createdAt?: Date,
  ) {}
}
```

## File: src/modules/rbac/domain/entities/user-role.entity.ts
```
import { Role } from './role.entity';

export class UserRole {
  constructor(
    public userId: number,
    public roleId: number,
    public assignedBy?: number,
    public expiresAt?: Date,
    public assignedAt?: Date,
    public role?: Role, // Optional relation
  ) {}

  isActive(): boolean {
    if (!this.expiresAt) return true;
    return new Date() < this.expiresAt;
  }
}
```

## File: src/modules/rbac/domain/repositories/rbac-repository.interface.ts
```
import { Role } from '../entities/role.entity';
import { Permission } from '../entities/permission.entity';
import { UserRole } from '../entities/user-role.entity';

export interface IRoleRepository {
  findByName(name: string): Promise<Role | null>;
  save(role: Role): Promise<Role>;
  findAllWithPermissions(roleIds: number[]): Promise<Role[]>;
  findAll(): Promise<Role[]>;
}

export interface IPermissionRepository {
  findByName(name: string): Promise<Permission | null>;
  save(permission: Permission): Promise<Permission>;
  findAll(): Promise<Permission[]>;
}

export interface IUserRoleRepository {
  findByUserId(userId: number): Promise<UserRole[]>;
  save(userRole: UserRole): Promise<void>;
  findOne(userId: number, roleId: number): Promise<UserRole | null>;
  delete(userId: number, roleId: number): Promise<void>;
}
```

## File: src/modules/rbac/domain/constants/rbac.constants.ts
```
export enum SystemRole {
  SUPER_ADMIN = 'SUPER_ADMIN',
  ADMIN = 'ADMIN',
  MANAGER = 'MANAGER',
  STAFF = 'STAFF',
  USER = 'USER',
  GUEST = 'GUEST',
}

export enum SystemPermission {
  // User permissions
  USER_CREATE = 'user:create',
  USER_READ = 'user:read',
  USER_UPDATE = 'user:update',
  USER_DELETE = 'user:delete',
  USER_MANAGE = 'user:manage',

  // Booking permissions
  BOOKING_CREATE = 'booking:create',
  BOOKING_READ = 'booking:read',
  BOOKING_UPDATE = 'booking:update',
  BOOKING_DELETE = 'booking:delete',
  BOOKING_MANAGE = 'booking:manage',

  // Payment permissions
  PAYMENT_PROCESS = 'payment:process',
  PAYMENT_REFUND = 'payment:refund',
  PAYMENT_VIEW = 'payment:view',

  // Report permissions
  REPORT_VIEW = 'report:view',
  REPORT_EXPORT = 'report:export',
  REPORT_MANAGE = 'report:manage',

  // System permissions
  SYSTEM_CONFIG = 'system:config',
  RBAC_MANAGE = 'rbac:manage',
  AUDIT_VIEW = 'audit:view',
}

export const ROLE_HIERARCHY: Record<SystemRole, number> = {
  [SystemRole.SUPER_ADMIN]: 100,
  [SystemRole.ADMIN]: 90,
  [SystemRole.MANAGER]: 80,
  [SystemRole.STAFF]: 70,
  [SystemRole.USER]: 60,
  [SystemRole.GUEST]: 50,
};

export const DEFAULT_ROLE = SystemRole.USER;
```

## File: src/modules/rbac/application/services/permission.service.ts
```
import { Injectable, Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import type {
  IUserRoleRepository,
  IRoleRepository,
} from '../../domain/repositories/rbac-repository.interface'; // FIX: import type

@Injectable()
export class PermissionService {
  private readonly CACHE_TTL = 300;
  private readonly CACHE_PREFIX = 'rbac:permissions:';

  constructor(
    @Inject('IUserRoleRepository') private userRoleRepo: IUserRoleRepository,
    @Inject('IRoleRepository') private roleRepo: IRoleRepository,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async userHasPermission(
    userId: number,
    permissionName: string,
  ): Promise<boolean> {
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;
    const cached = await this.cacheManager.get<string[]>(cacheKey);
    if (cached) return cached.includes(permissionName) || cached.includes('*');

    const userRoles = await this.userRoleRepo.findByUserId(userId);
    // Note: Assuming repo returns domain objects with populated role (if implemented that way)
    // or we fetch roles separately. For simplicity assuming basic flow:

    if (userRoles.length === 0) return false;
    const roleIds = userRoles.map((ur) => ur.roleId);

    const roles = await this.roleRepo.findAllWithPermissions(roleIds);

    const permissions = new Set<string>();
    roles.forEach((r) =>
      r.permissions?.forEach((p) => {
        if (p.isActive) permissions.add(p.name);
      }),
    );

    const permArray = Array.from(permissions);
    await this.cacheManager.set(cacheKey, permArray, this.CACHE_TTL);
    return permArray.includes(permissionName);
  }

  async assignRole(
    userId: number,
    roleId: number,
    assignedBy: number,
  ): Promise<void> {
    const existing = await this.userRoleRepo.findOne(userId, roleId);
    if (!existing) {
      // Construct basic UserRole object
      const userRole: any = {
        userId,
        roleId,
        assignedBy,
        assignedAt: new Date(),
      };
      await this.userRoleRepo.save(userRole);
      await this.cacheManager.del(`${this.CACHE_PREFIX}${userId}`);
    }
  }
}
```

## File: src/modules/rbac/application/services/role.service.ts
```
import { Injectable, Inject } from '@nestjs/common';
import type {
  IRoleRepository,
  IPermissionRepository,
} from '../../domain/repositories/rbac-repository.interface'; // FIX: import type
import { Role } from '../../domain/entities/role.entity';
import {
  SystemRole,
  SystemPermission,
} from '../../domain/constants/rbac.constants';

export interface AccessControlItem {
  role: string;
  resource: string;
  action: string;
  attributes: string;
}

@Injectable()
export class RoleService {
  constructor(
    @Inject('IRoleRepository') private roleRepo: IRoleRepository,
    @Inject('IPermissionRepository') private permRepo: IPermissionRepository,
  ) {}

  async createRole(data: any): Promise<Role> {
    const existing = await this.roleRepo.findByName(data.name);
    if (existing) throw new Error('Role exists');
    const role = new Role(
      undefined,
      data.name,
      data.description,
      true,
      data.isSystem,
    );
    return this.roleRepo.save(role);
  }

  async getAccessControlList(): Promise<AccessControlItem[]> {
    const roles = await this.roleRepo.findAll();
    const acl: AccessControlItem[] = [];
    roles.forEach((role) => {
      role.permissions.forEach((p) => {
        acl.push({
          role: role.name.toLowerCase(),
          resource: p.resourceType || '*',
          action: p.action || '*',
          attributes: p.attributes,
        });
      });
    });
    return acl;
  }

  // Seeder logic remains in seeder file mostly, but keeping init logic if needed
  async initializeSystemRoles(): Promise<void> {
    // Implementation placeholder if called from module init
  }
  async initializeSystemPermissions(): Promise<void> {
    // Implementation placeholder
  }
}
```

## File: src/modules/rbac/application/services/rbac-manager.service.ts
```
import { Injectable, Inject, Logger } from '@nestjs/common';
import type {
  IRoleRepository,
  IPermissionRepository,
} from '../../domain/repositories/rbac-repository.interface';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';

@Injectable()
export class RbacManagerService {
  private readonly logger = new Logger(RbacManagerService.name);

  constructor(
    @Inject('IRoleRepository') private roleRepo: IRoleRepository,
    @Inject('IPermissionRepository') private permRepo: IPermissionRepository,
  ) {}

  // Logic Import giữ nguyên (hoặc update full nếu cần)
  async importFromCsv(csvContent: string): Promise<any> {
    const lines = csvContent
      .split(/\r?\n/)
      .filter((line) => line.trim() !== '');
    if (lines.length > 0 && lines[0].toLowerCase().includes('role')) {
      lines.shift(); // Remove header
    }

    let createdCount = 0;
    let updatedCount = 0;

    for (const line of lines) {
      // CSV: role,resource,action,attributes,description
      const cols = line.split(',').map((c) => c.trim());
      if (cols.length < 3) continue;

      const [roleName, resource, action, attributes, description] = cols;

      // 1. Handle Permission
      const permName =
        resource === '*' ? 'manage:all' : `${resource}:${action}`;
      let perm = await this.permRepo.findByName(permName);

      if (!perm) {
        // Create new permission
        perm = new Permission(
          undefined,
          permName,
          description || '',
          resource,
          action,
          true,
          attributes || '*',
        );
        perm = await this.permRepo.save(perm);
        createdCount++;
      } else {
        // Update existing (optional logic)
        let changed = false;
        if (attributes && perm.attributes !== attributes) {
          perm.attributes = attributes;
          changed = true;
        }
        if (description && perm.description !== description) {
          perm.description = description;
          changed = true;
        }

        if (changed) {
          await this.permRepo.save(perm);
          updatedCount++;
        }
      }

      // 2. Handle Role
      let role = await this.roleRepo.findByName(roleName);
      if (!role) {
        role = new Role(
          undefined,
          roleName,
          'Imported from CSV',
          true,
          false,
          [],
        );
        role = await this.roleRepo.save(role);
      }

      // 3. Assign Permission to Role
      if (!role.permissions) role.permissions = [];
      const hasPerm = role.permissions.some((p) => p.name === perm!.name); // Domain logic check by name or ID

      if (!hasPerm) {
        role.permissions.push(perm!);
        await this.roleRepo.save(role);
      }
    }

    return { created: createdCount, updated: updatedCount };
  }

  // FIX: Logic Export đầy đủ
  async exportToCsv(): Promise<string> {
    // Repository phải đảm bảo load relation ['permissions']
    const roles = await this.roleRepo.findAll();

    const header = 'role,resource,action,attributes,description';
    const lines = [header];

    for (const role of roles) {
      if (!role.permissions || role.permissions.length === 0) {
        // Nếu Role không có quyền, in ra dòng rỗng để biết Role tồn tại
        lines.push(`${role.name},,,,`);
        continue;
      }

      for (const perm of role.permissions) {
        // Xử lý dữ liệu để tránh lỗi CSV
        const resource = perm.resourceType || '*';
        const action = perm.action || '*';
        const attributes = perm.attributes || '*';

        // Nếu description có dấu phẩy, bọc trong ngoặc kép
        let desc = perm.description || '';
        if (desc.includes(',')) {
          desc = `"${desc}"`;
        }

        const line = [role.name, resource, action, attributes, desc].join(',');

        lines.push(line);
      }
    }

    return lines.join('\n');
  }
}
```

## File: src/modules/rbac/infrastructure/controllers/role.controller.ts
```
import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiBody } from '@nestjs/swagger';
import { RoleService } from '../../application/services/role.service';
import { PermissionService } from '../../application/services/permission.service';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../guards/permission.guard';
import { Permissions } from '../decorators/permission.decorator';

@ApiTags('RBAC - Roles')
@ApiBearerAuth()
@Controller('rbac/roles')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class RoleController {
  constructor(
    private roleService: RoleService,
    private permissionService: PermissionService,
  ) {}

  @ApiOperation({ summary: 'Get all roles (Requires rbac:manage)' })
  @Get()
  @Permissions('rbac:manage')
  async getAllRoles() {
    return { message: 'Get all roles' };
  }

  @ApiOperation({ summary: 'Assign role to user' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        userId: { type: 'number', example: 1005 },
        roleId: { type: 'number', example: 2 },
      },
    },
  })
  @Post('assign')
  @Permissions('rbac:manage')
  async assignRole(@Body() body: { userId: number; roleId: number }) {
    await this.permissionService.assignRole(body.userId, body.roleId, 1);
    return { success: true, message: 'Role assigned' };
  }
}
```

## File: src/modules/rbac/infrastructure/controllers/rbac-manager.controller.ts
```
import {
  Controller,
  Post,
  Get,
  UseInterceptors,
  UploadedFile,
  UseGuards,
  BadRequestException,
  Res,
  StreamableFile,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiConsumes,
  ApiBody,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../guards/permission.guard';
import { Permissions } from '../decorators/permission.decorator';
import { RbacManagerService } from '../../application/services/rbac-manager.service';
import { BypassTransform } from '../../../../core/decorators/bypass-transform.decorator';

@ApiTags('RBAC - Import/Export')
@ApiBearerAuth()
@Controller('rbac/data')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class RbacManagerController {
  constructor(private rbacManagerService: RbacManagerService) {}

  @ApiOperation({ summary: 'Import RBAC Rules from CSV' })
  @ApiConsumes('multipart/form-data') // Báo cho Swagger biết đây là upload file
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          format: 'binary', // Định dạng file
        },
      },
    },
  })
  @Post('import')
  @Permissions('system:config')
  @UseInterceptors(FileInterceptor('file'))
  async importRbac(@UploadedFile() file: Express.Multer.File) {
    if (!file) {
      throw new BadRequestException('File is required');
    }

    if (!file.originalname.endsWith('.csv')) {
      throw new BadRequestException('Only .csv files are allowed');
    }

    const content = file.buffer.toString('utf-8');
    const result = await this.rbacManagerService.importFromCsv(content);

    return {
      success: true,
      message: 'RBAC data imported successfully',
      stats: result,
    };
  }

  @ApiOperation({ summary: 'Export RBAC Rules to CSV' })
  @Get('export')
  @Permissions('system:config')
  @BypassTransform()
  async exportRbac(@Res({ passthrough: true }) res: Response) {
    const csvData = await this.rbacManagerService.exportToCsv();

    res.set({
      'Content-Type': 'text/csv',
      'Content-Disposition': 'attachment; filename="rbac_rules.csv"',
    });

    return new StreamableFile(Buffer.from(csvData));
  }
}
```

## File: src/modules/rbac/infrastructure/guards/permission.guard.ts
```
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionService } from '../../application/services/permission.service';

@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private permissionService: PermissionService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
      'permissions',
      [context.getHandler(), context.getClass()],
    );

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('Authentication required');
    }

    // Check each required permission
    for (const permission of requiredPermissions) {
      const hasPermission = await this.permissionService.userHasPermission(
        user.id,
        permission,
      );

      if (!hasPermission) {
        throw new ForbiddenException(`Permission denied: ${permission}`);
      }
    }

    return true;
  }
}
```

## File: src/modules/rbac/infrastructure/decorators/permission.decorator.ts
```
import { SetMetadata } from '@nestjs/common';

export const PERMISSIONS_KEY = 'permissions';
export const Permissions = (...permissions: string[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);
```

## File: src/modules/rbac/infrastructure/persistence/entities/role.orm-entity.ts
```
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToMany,
  JoinTable,
  UpdateDateColumn,
} from 'typeorm';
import { PermissionOrmEntity } from './permission.orm-entity';

@Entity('roles')
export class RoleOrmEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true, length: 50 })
  name: string;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', nullable: true })
  description: string | null;

  @Column({ default: true })
  isActive: boolean;

  @Column({ default: false })
  isSystem: boolean;

  @ManyToMany(() => PermissionOrmEntity)
  @JoinTable({
    name: 'role_permissions',
    joinColumn: { name: 'role_id', referencedColumnName: 'id' },
    inverseJoinColumn: { name: 'permission_id', referencedColumnName: 'id' },
  })
  permissions: PermissionOrmEntity[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

## File: src/modules/rbac/infrastructure/persistence/entities/permission.orm-entity.ts
```
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';

@Entity('permissions')
export class PermissionOrmEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true, length: 100 })
  name: string;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', nullable: true })
  description: string | null;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', length: 50, nullable: true })
  resourceType: string | null;

  // FIX: Thêm type: 'varchar'
  @Column({ type: 'varchar', length: 50, nullable: true })
  action: string | null;

  @Column({ default: '*' })
  attributes: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;
}
```

## File: src/modules/rbac/infrastructure/persistence/entities/user-role.orm-entity.ts
```
import {
  Entity,
  Column,
  PrimaryColumn,
  CreateDateColumn,
  Index,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { RoleOrmEntity } from './role.orm-entity';

@Entity('user_roles')
@Index('idx_user_roles_user_id', ['userId'])
@Index('idx_user_roles_role_id', ['roleId'])
export class UserRoleOrmEntity {
  @PrimaryColumn('bigint')
  userId: number;

  @PrimaryColumn('int')
  roleId: number;

  // FIX: Thêm type: 'bigint'
  @Column({ type: 'bigint', nullable: true })
  assignedBy: number | null;

  // FIX: Thêm type: 'timestamptz'
  @Column({ type: 'timestamptz', nullable: true })
  expiresAt: Date | null;

  @CreateDateColumn()
  assignedAt: Date;

  @ManyToOne(() => RoleOrmEntity)
  @JoinColumn({ name: 'roleId' })
  role: RoleOrmEntity;
}
```

## File: src/modules/rbac/infrastructure/persistence/mappers/rbac.mapper.ts
```
import { Role } from '../../../domain/entities/role.entity'; // FIX: 3 dots
import { Permission } from '../../../domain/entities/permission.entity'; // FIX: 3 dots
import { UserRole } from '../../../domain/entities/user-role.entity'; // FIX: 3 dots
import { RoleOrmEntity } from '../entities/role.orm-entity';
import { PermissionOrmEntity } from '../entities/permission.orm-entity';
import { UserRoleOrmEntity } from '../entities/user-role.orm-entity';

export class RbacMapper {
  // PERMISSION
  static toPermissionDomain(
    orm: PermissionOrmEntity | null,
  ): Permission | null {
    if (!orm) return null;
    return new Permission(
      orm.id,
      orm.name,
      orm.description || undefined,
      orm.resourceType || undefined,
      orm.action || undefined,
      orm.isActive,
      orm.attributes,
      orm.createdAt,
    );
  }
  static toPermissionPersistence(domain: Permission): PermissionOrmEntity {
    const orm = new PermissionOrmEntity();
    if (domain.id) orm.id = domain.id;
    orm.name = domain.name;
    orm.description = domain.description || null;
    orm.resourceType = domain.resourceType || null;
    orm.action = domain.action || null;
    orm.isActive = domain.isActive;
    orm.attributes = domain.attributes;
    orm.createdAt = domain.createdAt || new Date();
    return orm;
  }

  // ROLE
  static toRoleDomain(orm: RoleOrmEntity | null): Role | null {
    if (!orm) return null;
    const perms = orm.permissions
      ? orm.permissions.map((p) => this.toPermissionDomain(p)!).filter(Boolean)
      : [];
    return new Role(
      orm.id,
      orm.name,
      orm.description || undefined,
      orm.isActive,
      orm.isSystem,
      perms,
      orm.createdAt,
      orm.updatedAt,
    );
  }
  static toRolePersistence(domain: Role): RoleOrmEntity {
    const orm = new RoleOrmEntity();
    if (domain.id) orm.id = domain.id;
    orm.name = domain.name;
    orm.description = domain.description || null;
    orm.isActive = domain.isActive;
    orm.isSystem = domain.isSystem;
    orm.permissions = domain.permissions.map((p) =>
      this.toPermissionPersistence(p),
    );
    orm.createdAt = domain.createdAt || new Date();
    orm.updatedAt = domain.updatedAt || new Date();
    return orm;
  }

  // USER ROLE
  static toUserRoleDomain(orm: UserRoleOrmEntity | null): UserRole | null {
    if (!orm) return null;
    const role = orm.role ? this.toRoleDomain(orm.role) : undefined;
    return new UserRole(
      Number(orm.userId),
      orm.roleId,
      orm.assignedBy ? Number(orm.assignedBy) : undefined,
      orm.expiresAt || undefined,
      orm.assignedAt,
      role!,
    );
  }
  static toUserRolePersistence(domain: UserRole): UserRoleOrmEntity {
    const orm = new UserRoleOrmEntity();
    orm.userId = domain.userId;
    orm.roleId = domain.roleId;
    orm.assignedBy = domain.assignedBy || null;
    orm.expiresAt = domain.expiresAt || null;
    orm.assignedAt = domain.assignedAt || new Date();
    return orm;
  }
}
```

## File: src/modules/rbac/infrastructure/persistence/repositories/typeorm-rbac.repositories.ts
```
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import {
  IRoleRepository,
  IPermissionRepository,
  IUserRoleRepository,
} from '../../../domain/repositories/rbac-repository.interface';
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';
import { RoleOrmEntity } from '../entities/role.orm-entity';
import { PermissionOrmEntity } from '../entities/permission.orm-entity';
import { UserRoleOrmEntity } from '../entities/user-role.orm-entity';
import { RbacMapper } from '../mappers/rbac.mapper';

@Injectable()
export class TypeOrmRoleRepository implements IRoleRepository {
  constructor(
    @InjectRepository(RoleOrmEntity) private repo: Repository<RoleOrmEntity>,
  ) {}

  async findByName(name: string): Promise<Role | null> {
    const entity = await this.repo.findOne({
      where: { name },
      relations: ['permissions'],
    });
    return RbacMapper.toRoleDomain(entity);
  }

  async save(role: Role): Promise<Role> {
    const orm = RbacMapper.toRolePersistence(role);
    const saved = await this.repo.save(orm);
    return RbacMapper.toRoleDomain(saved)!;
  }

  async findAllWithPermissions(roleIds: number[]): Promise<Role[]> {
    const entities = await this.repo.find({
      where: { id: In(roleIds), isActive: true },
      relations: ['permissions'],
    });
    return entities.map((e) => RbacMapper.toRoleDomain(e)!);
  }

  async findAll(): Promise<Role[]> {
    const entities = await this.repo.find({ relations: ['permissions'] });
    return entities.map((e) => RbacMapper.toRoleDomain(e)!);
  }
}

@Injectable()
export class TypeOrmPermissionRepository implements IPermissionRepository {
  constructor(
    @InjectRepository(PermissionOrmEntity)
    private repo: Repository<PermissionOrmEntity>,
  ) {}

  async findByName(name: string): Promise<Permission | null> {
    const entity = await this.repo.findOne({ where: { name } });
    return RbacMapper.toPermissionDomain(entity);
  }

  async save(permission: Permission): Promise<Permission> {
    const orm = RbacMapper.toPermissionPersistence(permission);
    const saved = await this.repo.save(orm);
    return RbacMapper.toPermissionDomain(saved)!;
  }

  async findAll(): Promise<Permission[]> {
    const entities = await this.repo.find();
    return entities.map((e) => RbacMapper.toPermissionDomain(e)!);
  }
}

@Injectable()
export class TypeOrmUserRoleRepository implements IUserRoleRepository {
  constructor(
    @InjectRepository(UserRoleOrmEntity)
    private repo: Repository<UserRoleOrmEntity>,
  ) {}

  async findByUserId(userId: number): Promise<UserRole[]> {
    const entities = await this.repo.find({
      where: { userId },
      relations: ['role'],
    });
    return entities.map((e) => RbacMapper.toUserRoleDomain(e)!);
  }

  async save(userRole: UserRole): Promise<void> {
    const orm = RbacMapper.toUserRolePersistence(userRole);
    await this.repo.save(orm);
  }

  async findOne(userId: number, roleId: number): Promise<UserRole | null> {
    const entity = await this.repo.findOne({ where: { userId, roleId } });
    return RbacMapper.toUserRoleDomain(entity);
  }

  async delete(userId: number, roleId: number): Promise<void> {
    await this.repo.delete({ userId, roleId });
  }
}
```

## File: src/modules/rbac/rbac.module.ts
```
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UserModule } from '../user/user.module';
import { RoleController } from './infrastructure/controllers/role.controller';
import { RbacManagerController } from './infrastructure/controllers/rbac-manager.controller';
import { PermissionService } from './application/services/permission.service';
import { RoleService } from './application/services/role.service';
import { RbacManagerService } from './application/services/rbac-manager.service';
import { PermissionGuard } from './infrastructure/guards/permission.guard';
// Infra Entities
import { RoleOrmEntity } from './infrastructure/persistence/entities/role.orm-entity';
import { PermissionOrmEntity } from './infrastructure/persistence/entities/permission.orm-entity';
import { UserRoleOrmEntity } from './infrastructure/persistence/entities/user-role.orm-entity';
// Repositories
import {
  TypeOrmRoleRepository,
  TypeOrmPermissionRepository,
  TypeOrmUserRoleRepository,
} from './infrastructure/persistence/repositories/typeorm-rbac.repositories';

@Module({
  imports: [
    UserModule,
    TypeOrmModule.forFeature([
      RoleOrmEntity,
      PermissionOrmEntity,
      UserRoleOrmEntity,
    ]),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (c: ConfigService) => ({ ttl: 300, max: 1000 }),
      inject: [ConfigService],
    }),
  ],
  controllers: [RoleController, RbacManagerController],
  providers: [
    PermissionService,
    RoleService,
    PermissionGuard,
    RbacManagerService,
    { provide: 'IRoleRepository', useClass: TypeOrmRoleRepository },
    { provide: 'IPermissionRepository', useClass: TypeOrmPermissionRepository },
    { provide: 'IUserRoleRepository', useClass: TypeOrmUserRoleRepository },
  ],
  exports: [PermissionService, PermissionGuard, RoleService],
})
export class RbacModule {}
```

## File: src/modules/shared/types/common.types.ts
```
export type ApiResponse<T = any> = {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  timestamp: Date;
};

export type PaginatedResponse<T> = ApiResponse<{
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}>;

export type JwtPayload = {
  sub: number;
  username: string;
  roles: string[];
  iat?: number;
  exp?: number;
};

export type UserContext = {
  id: number;
  username: string;
  roles: string[];
  permissions: string[];
};
```

## File: src/modules/shared/exceptions/rbac.exceptions.ts
```
import { HttpException, HttpStatus } from '@nestjs/common';

export class PermissionDeniedException extends HttpException {
  constructor(permission?: string) {
    const message = permission
      ? `Permission denied: ${permission}`
      : 'Insufficient permissions';
    super(message, HttpStatus.FORBIDDEN);
  }
}

export class RoleRequiredException extends HttpException {
  constructor(role: string) {
    super(`Role required: ${role}`, HttpStatus.FORBIDDEN);
  }
}

export class UserNotFoundException extends HttpException {
  constructor(userId?: number) {
    const message = userId ? `User not found: ${userId}` : 'User not found';
    super(message, HttpStatus.NOT_FOUND);
  }
}

export class InvalidCredentialsException extends HttpException {
  constructor() {
    super('Invalid credentials', HttpStatus.UNAUTHORIZED);
  }
}
```

## File: src/modules/shared/utils/password.util.ts
```
import * as bcrypt from 'bcrypt';

export class PasswordUtil {
  static async hash(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  }

  static async compare(
    plainText: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(plainText, hashedPassword);
  }

  static validateStrength(password: string): boolean {
    // At least 8 chars, 1 uppercase, 1 lowercase, 1 number
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    return regex.test(password);
  }
}
```

## File: src/modules/shared/shared.module.ts
```
import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmTransactionManager } from '../../core/shared/infrastructure/persistence/typeorm-transaction.manager';

@Global()
@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' })],
  providers: [
    {
      provide: 'ITransactionManager',
      useClass: TypeOrmTransactionManager,
    },
  ],
  exports: [ConfigModule, 'ITransactionManager'],
})
export class SharedModule {}
```

## File: src/modules/test/seeders/database.seeder.ts
```
import { Injectable, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { UserOrmEntity } from '../../user/infrastructure/persistence/entities/user.orm-entity';
import { RoleOrmEntity } from '../../rbac/infrastructure/persistence/entities/role.orm-entity';
import { PermissionOrmEntity } from '../../rbac/infrastructure/persistence/entities/permission.orm-entity';
import { UserRoleOrmEntity } from '../../rbac/infrastructure/persistence/entities/user-role.orm-entity';
import {
  SystemPermission,
  SystemRole,
} from '../../rbac/domain/constants/rbac.constants';

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  constructor(
    @InjectRepository(UserOrmEntity) private uRepo: Repository<UserOrmEntity>,
    @InjectRepository(RoleOrmEntity) private rRepo: Repository<RoleOrmEntity>,
    @InjectRepository(PermissionOrmEntity)
    private pRepo: Repository<PermissionOrmEntity>,
    @InjectRepository(UserRoleOrmEntity)
    private urRepo: Repository<UserRoleOrmEntity>,
  ) {}

  async onModuleInit() {
    if (process.env.NODE_ENV !== 'development') return;
    console.log('Seeding...');
    await this.seedPerms();
    await this.seedRoles();
    await this.seedUsers();
    await this.assign();
    console.log('Seeded.');
  }

  async seedPerms() {
    for (const name of Object.values(SystemPermission)) {
      const [res, act] = name.split(':');
      if (!(await this.pRepo.findOne({ where: { name } }))) {
        await this.pRepo.save(
          this.pRepo.create({
            name,
            resourceType: res,
            action: act,
            isActive: true,
          }),
        );
      }
    }
  }

  async seedRoles() {
    for (const name of Object.values(SystemRole)) {
      if (!(await this.rRepo.findOne({ where: { name } }))) {
        await this.rRepo.save(
          this.rRepo.create({ name, isSystem: true, isActive: true }),
        );
      }
    }
  }

  async seedUsers() {
    const pw = await bcrypt.hash('123456', 10);
    const users = [
      {
        username: 'superadmin',
        fullName: 'Super Admin',
        email: 'admin@test.com',
      },
      { username: 'user1', fullName: 'Normal User', email: 'user@test.com' },
    ];
    for (const u of users) {
      if (!(await this.uRepo.findOne({ where: { username: u.username } }))) {
        await this.uRepo.save(
          this.uRepo.create({
            ...u,
            hashedPassword: pw,
            isActive: true,
            createdAt: new Date(),
          }),
        );
      }
    }
  }

  async assign() {
    const adminRole = await this.rRepo.findOne({
      where: { name: SystemRole.SUPER_ADMIN },
      relations: ['permissions'],
    });
    if (!adminRole) return;

    // Assign all perms to superadmin
    const allPerms = await this.pRepo.find();
    adminRole.permissions = allPerms;
    await this.rRepo.save(adminRole);

    const adminUser = await this.uRepo.findOne({
      where: { username: 'superadmin' },
    });
    if (adminUser) {
      const ur = await this.urRepo.findOne({
        where: { userId: adminUser.id, roleId: adminRole.id },
      });
      if (!ur)
        await this.urRepo.save({
          userId: adminUser.id,
          roleId: adminRole.id,
          assignedAt: new Date(),
        });
    }
  }
}
```

## File: src/modules/test/controllers/test.controller.ts
```
import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../../rbac/infrastructure/guards/permission.guard';
import { Permissions } from '../../rbac/infrastructure/decorators/permission.decorator';
import { Public } from '../../auth/infrastructure/decorators/public.decorator';
import { CurrentUser } from '../../auth/infrastructure/decorators/current-user.decorator';

@Controller('test')
export class TestController {
  @Public()
  @Get('health')
  healthCheck() {
    return {
      status: 'OK',
      timestamp: new Date(),
      service: 'RBAC System',
      version: '1.0.0',
    };
  }

  @Get('protected')
  @UseGuards(JwtAuthGuard)
  protectedRoute(@CurrentUser() user: any) {
    return {
      message: 'This is a protected route',
      user: {
        id: user.id,
        username: user.username,
        roles: user.roles,
      },
    };
  }

  @Get('admin-only')
  @UseGuards(JwtAuthGuard, PermissionGuard)
  @Permissions('rbac:manage')
  adminOnly(@CurrentUser() user: any) {
    return {
      message: 'This is admin-only route',
      user: {
        id: user.id,
        username: user.username,
      },
    };
  }

  @Get('user-management')
  @UseGuards(JwtAuthGuard, PermissionGuard)
  @Permissions('user:manage')
  userManagement(@CurrentUser() user: any) {
    return {
      message: 'You have user management permission',
      user: {
        id: user.id,
        username: user.username,
      },
    };
  }
}
```

## File: src/modules/test/test.module.ts
```
import { Module, OnModuleInit } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from '../user/user.module';
import { RbacModule } from '../rbac/rbac.module';
import { DatabaseSeeder } from './seeders/database.seeder';
import { TestController } from './controllers/test.controller';
import { UserOrmEntity } from '../user/infrastructure/persistence/entities/user.orm-entity';
import { RoleOrmEntity } from '../rbac/infrastructure/persistence/entities/role.orm-entity';
import { PermissionOrmEntity } from '../rbac/infrastructure/persistence/entities/permission.orm-entity';
import { UserRoleOrmEntity } from '../rbac/infrastructure/persistence/entities/user-role.orm-entity';

@Module({
  imports: [
    UserModule,
    RbacModule,
    TypeOrmModule.forFeature([
      UserOrmEntity,
      RoleOrmEntity,
      PermissionOrmEntity,
      UserRoleOrmEntity,
    ]),
  ],
  controllers: [TestController],
  providers: [DatabaseSeeder],
})
export class TestModule implements OnModuleInit {
  constructor(private s: DatabaseSeeder) {}
  async onModuleInit() {
    await this.s.onModuleInit();
  }
}
```

## File: src/core/interceptors/transform-response.interceptor.ts
```
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  StreamableFile,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { BYPASS_TRANSFORM_KEY } from '../decorators/bypass-transform.decorator';

@Injectable()
export class TransformResponseInterceptor<T> implements NestInterceptor<
  T,
  any
> {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // 1. Check xem có gắn cờ Bypass không
    const bypass = this.reflector.get<boolean>(
      BYPASS_TRANSFORM_KEY,
      context.getHandler(),
    );

    if (bypass) {
      return next.handle();
    }

    // 2. Logic bọc JSON bình thường
    return next.handle().pipe(
      map((data) => {
        // Double check: Nếu data là StreamableFile thì cũng không bọc
        if (data instanceof StreamableFile) {
          return data;
        }

        return {
          success: true,
          statusCode: context.switchToHttp().getResponse().statusCode,
          message:
            this.reflector.get<string>(
              'response_message',
              context.getHandler(),
            ) || 'Success',
          result: data,
        };
      }),
    );
  }
}
```

## File: src/core/filters/http-exception.filter.ts
```
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status = exception.getStatus
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionResponse: any = exception.getResponse();
    const errorMsg = exceptionResponse.message;

    const responseBody = {
      success: false,
      statusCode: status,
      message:
        typeof exceptionResponse === 'string' ? exceptionResponse : 'Error',
      errors: errorMsg || null,
      path: request.url,
      timestamp: new Date().toISOString(),
    };

    if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
      responseBody.message =
        exceptionResponse['error'] || exceptionResponse['message'];
      responseBody.errors = exceptionResponse['message'];
    }

    response.status(status).json(responseBody);
  }
}
```

## File: src/core/core.module.ts
```
import { Module } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';

import { TransformResponseInterceptor } from './interceptors/transform-response.interceptor';
import { HttpExceptionFilter } from './filters/http-exception.filter';

@Module({
  providers: [
    {
      provide: APP_PIPE,
      useValue: new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformResponseInterceptor,
    },
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
})
export class CoreModule {}
```

## File: src/core/decorators/bypass-transform.decorator.ts
```
import { SetMetadata } from '@nestjs/common';

export const BYPASS_TRANSFORM_KEY = 'bypass_transform';
export const BypassTransform = () => SetMetadata(BYPASS_TRANSFORM_KEY, true);
```

## File: src/core/shared/application/ports/file-parser.port.ts
```
export interface IFileParser {
  parseCsv<T>(content: string): T[];
}
```

## File: src/core/shared/application/ports/transaction-manager.port.ts
```
export type Transaction = unknown; // Opaque type

export interface ITransactionManager {
  runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T>;
}
```

## File: src/core/shared/application/ports/repository.port.ts
```
import { Transaction } from './transaction-manager.port';

export interface IRepository<T, ID> {
  findById(id: ID, tx?: Transaction): Promise<T | null>;
  findAll(criteria?: Partial<T>, tx?: Transaction): Promise<T[]>;
  // FIX: save trả về Promise<T> thay vì void để đồng bộ với User Repo
  save(entity: T, tx?: Transaction): Promise<T>;
  delete(id: ID, tx?: Transaction): Promise<void>;
  exists(id: ID, tx?: Transaction): Promise<boolean>;
}

export interface IPaginatedRepository<T, ID> extends IRepository<T, ID> {
  findPaginated(
    page: number,
    limit: number,
    criteria?: Partial<T>,
    sort?: { field: string; order: 'ASC' | 'DESC' },
  ): Promise<{ data: T[]; total: number; page: number; totalPages: number }>;
}
```

## File: src/core/shared/infrastructure/adapters/csv-parser.adapter.ts
```
import { Injectable } from '@nestjs/common';
import { IFileParser } from '../../application/ports/file-parser.port';

@Injectable()
export class CsvParserAdapter implements IFileParser {
  parseCsv<T>(content: string): T[] {
    const lines = content.split(/\r?\n/).filter((line) => line.trim() !== '');
    if (lines.length === 0) return [];

    const headers = lines[0].split(',').map((h) => h.trim()); // Simple split
    // In real app, use a library like 'csv-parse'
    return []; // Placeholder implementation logic moved from service
  }
}
```

## File: src/core/shared/infrastructure/persistence/typeorm-transaction.manager.ts
```
import { Injectable } from '@nestjs/common';
import { DataSource, EntityManager } from 'typeorm';
import {
  ITransactionManager,
  Transaction,
} from '../../application/ports/transaction-manager.port';

@Injectable()
export class TypeOrmTransactionManager implements ITransactionManager {
  constructor(private dataSource: DataSource) {}

  async runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
    return this.dataSource.transaction(async (entityManager: EntityManager) => {
      // Ép kiểu EntityManager thành Transaction (unknown) để truyền xuống dưới
      return work(entityManager as unknown as Transaction);
    });
  }
}
```

## File: src/core/shared/infrastructure/persistence/abstract-typeorm.repository.ts
```
import {
  Repository,
  DeepPartial,
  ObjectLiteral,
  FindOptionsWhere,
  EntityManager,
} from 'typeorm';
import { IRepository } from '../../application/ports/repository.port';
import { Transaction } from '../../application/ports/transaction-manager.port';

export abstract class AbstractTypeOrmRepository<
  T extends ObjectLiteral,
> implements IRepository<T, any> {
  protected constructor(protected readonly repository: Repository<T>) {}

  protected getRepository(tx?: Transaction): Repository<T> {
    if (tx) {
      const entityManager = tx as EntityManager;
      return entityManager.getRepository(this.repository.target);
    }
    return this.repository;
  }

  async findById(id: any, tx?: Transaction): Promise<T | null> {
    const repo = this.getRepository(tx);
    const options = { where: { id } as unknown as FindOptionsWhere<T> };
    return repo.findOne(options);
  }

  async findAll(criteria?: Partial<T>, tx?: Transaction): Promise<T[]> {
    const repo = this.getRepository(tx);
    if (criteria) {
      return repo.find({ where: criteria as FindOptionsWhere<T> });
    }
    return repo.find();
  }

  // FIX: Return Promise<T> instead of Promise<void>
  async save(entity: T, tx?: Transaction): Promise<T> {
    const repo = this.getRepository(tx);
    // TypeORM .save() returns the saved entity
    return repo.save(entity as DeepPartial<T>) as Promise<T>;
  }

  async delete(id: any, tx?: Transaction): Promise<void> {
    const repo = this.getRepository(tx);
    await repo.delete(id);
  }

  async exists(id: any, tx?: Transaction): Promise<boolean> {
    const entity = await this.findById(id, tx);
    return !!entity;
  }
}
```

## File: src/config/app.config.ts
```
import { registerAs } from '@nestjs/config';

export default registerAs('app', () => ({
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '3000', 10),
  apiPrefix: 'api',
}));
```

## File: src/config/database.config.ts
```
import { registerAs } from '@nestjs/config';

export default registerAs('database', () => {
  const isDev = process.env.NODE_ENV === 'development';

  return {
    type: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_NAME || 'rbac_system',

    // PRO TIP:
    // Trên Production nên tắt synchronize (false) và dùng migrationsRun (true)
    // Ở Dev có thể để synchronize true cho lẹ, nhưng dùng Migration an toàn hơn
    synchronize: isDev,
    logging: isDev ? ['error', 'warn', 'migration'] : ['error'],

    // --- MIGRATION CONFIG ---
    migrationsRun: true, // Tự động chạy migration khi start app
    migrations: [__dirname + '/../database/migrations/*{.ts,.js}'],
    // ------------------------

    autoLoadEntities: true,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  };
});
```

## File: src/config/logging.config.ts
```
import { registerAs } from '@nestjs/config';

export default registerAs('logging', () => ({
  level: process.env.LOG_LEVEL || 'info',
}));
```

## File: src/database/migrations/1700000000000-add-attributes-to-permission.ts
```
import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddAttributesToPermission1700000000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // 1. Lấy thông tin bảng permissions
    const table = await queryRunner.getTable('permissions');

    // 2. Kiểm tra xem cột 'attributes' đã tồn tại chưa
    const attributeColumn = table?.findColumnByName('attributes');

    // 3. Nếu chưa có thì thêm vào
    if (!attributeColumn) {
      await queryRunner.addColumn(
        'permissions',
        new TableColumn({
          name: 'attributes',
          type: 'varchar',
          default: "'*'", // Mặc định là dấu sao (Full quyền)
          isNullable: false,
        }),
      );
      console.log(
        '✅ MIGRATION: Added "attributes" column to "permissions" table.',
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Logic Rollback: Nếu chạy revert thì xóa cột đi
    const table = await queryRunner.getTable('permissions');
    const attributeColumn = table?.findColumnByName('attributes');

    if (attributeColumn) {
      await queryRunner.dropColumn('permissions', 'attributes');
    }
  }
}
```

