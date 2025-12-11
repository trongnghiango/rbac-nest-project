## File: src/bootstrap/app.module.ts
```
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';

import databaseConfig from '../config/database.config';
import appConfig from '../config/app.config';
import loggingConfig from '../config/logging.config';

import { CoreModule } from '../core/core.module';
import { SharedModule } from '../modules/shared/shared.module';
import { DrizzleModule } from '../database/drizzle.module'; // NEW

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
    DrizzleModule, // Thay thế TypeOrmModule
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

## File: src/modules/auth/infrastructure/persistence/mappers/session.mapper.ts
```
import { InferSelectModel } from 'drizzle-orm';
import { Session } from '../../../domain/entities/session.entity';
import { sessions } from '../../../../../database/schema';

type SessionRecord = InferSelectModel<typeof sessions>;

export class SessionMapper {
  static toDomain(raw: SessionRecord | null): Session | null {
    if (!raw) return null;
    return new Session(
      raw.id,
      Number(raw.userId),
      raw.token,
      raw.expiresAt,
      raw.ipAddress || undefined,
      raw.userAgent || undefined,
      raw.createdAt,
    );
  }

  static toPersistence(domain: Session) {
    return {
      id: domain.id, // UUID thì có thể truyền vào hoặc để DB tự gen
      userId: domain.userId,
      token: domain.token,
      expiresAt: domain.expiresAt,
      ipAddress: domain.ipAddress || null,
      userAgent: domain.userAgent || null,
      createdAt: domain.createdAt || new Date(),
    };
  }
}
```

## File: src/modules/auth/infrastructure/persistence/drizzle-session.repository.ts
```
import { Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { ISessionRepository } from '../../domain/repositories/session-repository.interface';
import { Session } from '../../domain/entities/session.entity';
import { DrizzleBaseRepository } from '../../../../core/shared/infrastructure/persistence/drizzle-base.repository';
import { sessions } from '../../../../database/schema';
import { SessionMapper } from './mappers/session.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleSessionRepository
  extends DrizzleBaseRepository
  implements ISessionRepository
{
  async create(session: Session, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    const data = SessionMapper.toPersistence(session);
    // UUID thường được generate từ code hoặc DB.
    // Nếu ID có giá trị thì insert, ko thì để default (gen_random_uuid)
    if (data.id) {
      await db.insert(sessions).values(data as any);
    } else {
      const { id, ...insertData } = data;
      await db.insert(sessions).values(insertData);
    }
  }

  async findByUserId(userId: number): Promise<Session[]> {
    const results = await this.db
      .select()
      .from(sessions)
      .where(eq(sessions.userId, userId));
    return results.map((r) => SessionMapper.toDomain(r)!);
  }

  async deleteByUserId(userId: number): Promise<void> {
    await this.db.delete(sessions).where(eq(sessions.userId, userId));
  }
}
```

## File: src/modules/auth/auth.module.ts
```
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UserModule } from '../user/user.module';
import { AuthenticationService } from './application/services/authentication.service';
import { JwtStrategy } from './infrastructure/strategies/jwt.strategy';
import { JwtAuthGuard } from './infrastructure/guards/jwt-auth.guard';
import { AuthController } from './infrastructure/controllers/auth.controller';
import { DrizzleSessionRepository } from './infrastructure/persistence/drizzle-session.repository';

@Module({
  imports: [
    UserModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        secret: config.get('JWT_SECRET') || 'secret',
        signOptions: { expiresIn: '1d' },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthenticationService,
    JwtStrategy,
    JwtAuthGuard,
    { provide: 'ISessionRepository', useClass: DrizzleSessionRepository },
  ],
  exports: [JwtAuthGuard, AuthenticationService, JwtModule],
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

## File: src/modules/user/infrastructure/persistence/mappers/user.mapper.ts
```
import { InferSelectModel } from 'drizzle-orm';
import { User } from '../../../domain/entities/user.entity';
import { users } from '../../../../../database/schema';

// Tự động lấy Type từ Schema Definition
type UserRecord = InferSelectModel<typeof users>;

export class UserMapper {
  static toDomain(raw: UserRecord | null): User | null {
    if (!raw) return null;

    return new User(
      raw.id,
      raw.username,
      raw.email || undefined,
      raw.hashedPassword || undefined,
      raw.fullName || undefined,
      raw.isActive || false,
      raw.phoneNumber || undefined,
      raw.avatarUrl || undefined,
      (raw.profile as any) || undefined, // JSONB cần cast nhẹ hoặc định nghĩa type riêng
      raw.createdAt || undefined,
      raw.updatedAt || undefined,
    );
  }

  static toPersistence(domain: User) {
    return {
      id: domain.id, // Có thể undefined
      username: domain.username,
      email: domain.email || null,
      hashedPassword: domain.hashedPassword || null,
      fullName: domain.fullName || null,
      isActive: domain.isActive,
      phoneNumber: domain.phoneNumber || null,
      avatarUrl: domain.avatarUrl || null,
      profile: domain.profile || null,
      createdAt: domain.createdAt || new Date(),
      updatedAt: domain.updatedAt || new Date(),
    };
  }
}
```

## File: src/modules/user/infrastructure/persistence/drizzle-user.repository.ts
```
import { Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { User } from '../../domain/entities/user.entity';
import { DrizzleBaseRepository } from '../../../../core/shared/infrastructure/persistence/drizzle-base.repository';
import { users } from '../../../../database/schema';
import { UserMapper } from './mappers/user.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleUserRepository
  extends DrizzleBaseRepository
  implements IUserRepository
{
  async findById(id: number, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(users).where(eq(users.id, id));
    return UserMapper.toDomain(result[0]);
  }

  async findByUsername(
    username: string,
    tx?: Transaction,
  ): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db
      .select()
      .from(users)
      .where(eq(users.username, username));
    return UserMapper.toDomain(result[0]);
  }

  async findByEmail(email: string, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(users).where(eq(users.email, email));
    return UserMapper.toDomain(result[0]);
  }

  async findAllActive(): Promise<User[]> {
    const result = await this.db
      .select()
      .from(users)
      .where(eq(users.isActive, true));
    return result.map((u) => UserMapper.toDomain(u)!);
  }

  async save(user: User, tx?: Transaction): Promise<User> {
    const db = this.getDb(tx);
    const data = UserMapper.toPersistence(user);

    let result;
    if (data.id) {
      // UPDATE: Chỉ update khi có ID
      result = await db
        .update(users)
        .set(data)
        .where(eq(users.id, data.id))
        .returning();
    } else {
      // INSERT: Loại bỏ ID để Postgres tự sinh (Serial)
      // Tránh lỗi lệch sequence
      const { id, ...insertData } = data;
      result = await db.insert(users).values(insertData).returning();
    }

    return UserMapper.toDomain(result[0])!;
  }

  async findAll(): Promise<User[]> {
    return [];
  }
  async update(): Promise<User> {
    throw new Error('Use save');
  }
  async delete(id: number, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    await db.delete(users).where(eq(users.id, id));
  }
  async exists(id: number, tx?: Transaction): Promise<boolean> {
    const u = await this.findById(id, tx);
    return !!u;
  }
  async count(): Promise<number> {
    return 0;
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
import { UserService } from './application/services/user.service';
import { UserController } from './infrastructure/controllers/user.controller';
import { DrizzleUserRepository } from './infrastructure/persistence/drizzle-user.repository';

@Module({
  imports: [], // Không cần TypeOrmModule nữa
  controllers: [UserController],
  providers: [
    UserService,
    {
      provide: 'IUserRepository',
      useClass: DrizzleUserRepository,
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
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

export interface IRoleRepository {
  findByName(name: string, tx?: Transaction): Promise<Role | null>;
  save(role: Role, tx?: Transaction): Promise<Role>;
  findAllWithPermissions(roleIds: number[], tx?: Transaction): Promise<Role[]>;
  findAll(tx?: Transaction): Promise<Role[]>;
}

export interface IPermissionRepository {
  findByName(name: string, tx?: Transaction): Promise<Permission | null>;
  save(permission: Permission, tx?: Transaction): Promise<Permission>;
  findAll(tx?: Transaction): Promise<Permission[]>;
}

export interface IUserRoleRepository {
  findByUserId(userId: number, tx?: Transaction): Promise<UserRole[]>;
  save(userRole: UserRole, tx?: Transaction): Promise<void>;
  findOne(
    userId: number,
    roleId: number,
    tx?: Transaction,
  ): Promise<UserRole | null>;
  delete(userId: number, roleId: number, tx?: Transaction): Promise<void>;
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

## File: src/modules/rbac/infrastructure/persistence/mappers/rbac.mapper.ts
```
import { InferSelectModel } from 'drizzle-orm';
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';
import { roles, permissions, userRoles } from '../../../../../database/schema';

// Định nghĩa Type dựa trên Schema
type RoleRecord = InferSelectModel<typeof roles>;
type PermissionRecord = InferSelectModel<typeof permissions>;
type UserRoleRecord = InferSelectModel<typeof userRoles>;

// Type phức tạp cho Relation (Kết quả trả về từ db.query...)
type RoleWithPermissions = RoleRecord & {
  permissions: { permission: PermissionRecord }[];
};
type UserRoleWithRole = UserRoleRecord & {
  role: RoleRecord;
};

export class RbacMapper {
  // PERMISSION
  static toPermissionDomain(raw: PermissionRecord | null): Permission | null {
    if (!raw) return null;
    return new Permission(
      raw.id,
      raw.name,
      raw.description || undefined,
      raw.resourceType || undefined,
      raw.action || undefined,
      raw.isActive || false,
      raw.attributes || '*',
      raw.createdAt || undefined,
    );
  }

  static toPermissionPersistence(domain: Permission) {
    return {
      id: domain.id,
      name: domain.name,
      description: domain.description || null,
      resourceType: domain.resourceType || null,
      action: domain.action || null,
      isActive: domain.isActive,
      attributes: domain.attributes,
      createdAt: domain.createdAt || new Date(),
    };
  }

  // ROLE (Handle Relation Type Safety)
  static toRoleDomain(
    raw: RoleWithPermissions | RoleRecord | null,
  ): Role | null {
    if (!raw) return null;

    // Check if it has nested permissions
    let perms: Permission[] = [];
    if ('permissions' in raw && Array.isArray(raw.permissions)) {
      perms = raw.permissions
        .map((rp) => this.toPermissionDomain(rp.permission)!)
        .filter(Boolean);
    }

    return new Role(
      raw.id,
      raw.name,
      raw.description || undefined,
      raw.isActive || false,
      raw.isSystem || false,
      perms,
      raw.createdAt || undefined,
      raw.updatedAt || undefined,
    );
  }

  static toRolePersistence(domain: Role) {
    return {
      id: domain.id,
      name: domain.name,
      description: domain.description || null,
      isActive: domain.isActive,
      isSystem: domain.isSystem,
      createdAt: domain.createdAt || new Date(),
      updatedAt: domain.updatedAt || new Date(),
    };
  }

  // USER ROLE
  static toUserRoleDomain(
    raw: UserRoleWithRole | UserRoleRecord | null,
  ): UserRole | null {
    if (!raw) return null;

    let role;
    if ('role' in raw && raw.role) {
      role = this.toRoleDomain(raw.role);
    }

    return new UserRole(
      Number(raw.userId),
      raw.roleId,
      raw.assignedBy ? Number(raw.assignedBy) : undefined,
      raw.expiresAt || undefined,
      raw.assignedAt || undefined,
      role!,
    );
  }

  static toUserRolePersistence(domain: UserRole) {
    return {
      userId: domain.userId,
      roleId: domain.roleId,
      assignedBy: domain.assignedBy || null,
      expiresAt: domain.expiresAt || null,
      assignedAt: domain.assignedAt || new Date(),
    };
  }
}
```

## File: src/modules/rbac/infrastructure/persistence/repositories/drizzle-rbac.repositories.ts
```
import { Injectable } from '@nestjs/common';
import { eq, inArray, and } from 'drizzle-orm';
import {
  IRoleRepository,
  IPermissionRepository,
  IUserRoleRepository,
} from '../../../domain/repositories/rbac-repository.interface';
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';
import { DrizzleBaseRepository } from '../../../../../core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  roles,
  permissions,
  userRoles,
  rolePermissions,
} from '../../../../../database/schema';
import { RbacMapper } from '../mappers/rbac.mapper';
import { Transaction } from '../../../../../core/shared/application/ports/transaction-manager.port';

// --- ROLE REPOSITORY ---
@Injectable()
export class DrizzleRoleRepository
  extends DrizzleBaseRepository
  implements IRoleRepository
{
  async findByName(name: string, tx?: Transaction): Promise<Role | null> {
    const db = this.getDb(tx);
    const result = await db.query.roles.findFirst({
      where: eq(roles.name, name),
      with: {
        permissions: {
          with: { permission: true },
        },
      },
    });

    return result ? RbacMapper.toRoleDomain(result as any) : null;
  }

  async save(role: Role, tx?: Transaction): Promise<Role> {
    const db = this.getDb(tx);
    const data = RbacMapper.toRolePersistence(role);

    return await db.transaction(async (trx) => {
      let savedRoleId: number;

      // SAFE UPSERT LOGIC
      if (data.id) {
        await trx.update(roles).set(data).where(eq(roles.id, data.id));
        savedRoleId = data.id;
      } else {
        const { id, ...insertData } = data;
        const res = await trx
          .insert(roles)
          .values(insertData)
          .returning({ id: roles.id });
        savedRoleId = res[0].id;
      }

      // Handle Permissions Relation
      if (role.permissions && role.permissions.length > 0) {
        await trx
          .delete(rolePermissions)
          .where(eq(rolePermissions.roleId, savedRoleId));

        const permInserts = role.permissions.map((p) => ({
          roleId: savedRoleId,
          permissionId: p.id!,
        }));

        if (permInserts.length > 0) {
          await trx.insert(rolePermissions).values(permInserts);
        }
      }

      // Return full object by refetching
      const finalRole = await this.findByName(
        role.name,
        trx as unknown as Transaction,
      );
      return finalRole!;
    });
  }

  async findAllWithPermissions(
    roleIds: number[],
    tx?: Transaction,
  ): Promise<Role[]> {
    const db = this.getDb(tx);
    const results = await db.query.roles.findMany({
      where: inArray(roles.id, roleIds),
      with: { permissions: { with: { permission: true } } },
    });
    return results.map((r) => RbacMapper.toRoleDomain(r as any)!);
  }

  async findAll(tx?: Transaction): Promise<Role[]> {
    const db = this.getDb(tx);
    const results = await db.query.roles.findMany({
      with: { permissions: { with: { permission: true } } },
    });
    return results.map((r) => RbacMapper.toRoleDomain(r as any)!);
  }
}

// --- PERMISSION REPOSITORY ---
@Injectable()
export class DrizzlePermissionRepository
  extends DrizzleBaseRepository
  implements IPermissionRepository
{
  async findByName(name: string, tx?: Transaction): Promise<Permission | null> {
    const db = this.getDb(tx);
    const result = await db
      .select()
      .from(permissions)
      .where(eq(permissions.name, name));
    return RbacMapper.toPermissionDomain(result[0]);
  }

  async save(permission: Permission, tx?: Transaction): Promise<Permission> {
    const db = this.getDb(tx);
    const data = RbacMapper.toPermissionPersistence(permission);

    let result;
    if (data.id) {
      result = await db
        .update(permissions)
        .set(data)
        .where(eq(permissions.id, data.id))
        .returning();
    } else {
      const { id, ...insertData } = data;
      result = await db.insert(permissions).values(insertData).returning();
    }

    return RbacMapper.toPermissionDomain(result[0])!;
  }

  async findAll(tx?: Transaction): Promise<Permission[]> {
    const db = this.getDb(tx);
    const results = await db.select().from(permissions);
    return results.map((r) => RbacMapper.toPermissionDomain(r)!);
  }
}

// --- USER ROLE REPOSITORY ---
@Injectable()
export class DrizzleUserRoleRepository
  extends DrizzleBaseRepository
  implements IUserRoleRepository
{
  async findByUserId(userId: number, tx?: Transaction): Promise<UserRole[]> {
    const db = this.getDb(tx);
    const results = await db.query.userRoles.findMany({
      where: eq(userRoles.userId, userId),
      with: { role: true },
    });
    return results.map((r) => RbacMapper.toUserRoleDomain(r as any)!);
  }

  async save(userRole: UserRole, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    const data = RbacMapper.toUserRolePersistence(userRole);

    // Manual Upsert for Composite Key
    await db
      .insert(userRoles)
      .values(data)
      .onConflictDoUpdate({
        target: [userRoles.userId, userRoles.roleId],
        set: { expiresAt: data.expiresAt, assignedBy: data.assignedBy },
      });
  }

  async findOne(
    userId: number,
    roleId: number,
    tx?: Transaction,
  ): Promise<UserRole | null> {
    const db = this.getDb(tx);
    const result = await db.query.userRoles.findFirst({
      where: and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)),
      with: { role: true },
    });
    return result ? RbacMapper.toUserRoleDomain(result as any) : null;
  }

  async delete(
    userId: number,
    roleId: number,
    tx?: Transaction,
  ): Promise<void> {
    const db = this.getDb(tx);
    await db
      .delete(userRoles)
      .where(and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)));
  }
}
```

## File: src/modules/rbac/rbac.module.ts
```
import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UserModule } from '../user/user.module';
import { RoleController } from './infrastructure/controllers/role.controller';
import { RbacManagerController } from './infrastructure/controllers/rbac-manager.controller';
import { PermissionService } from './application/services/permission.service';
import { RoleService } from './application/services/role.service';
import { RbacManagerService } from './application/services/rbac-manager.service';
import { PermissionGuard } from './infrastructure/guards/permission.guard';
// Drizzle Repositories
import {
  DrizzleRoleRepository,
  DrizzlePermissionRepository,
  DrizzleUserRoleRepository,
} from './infrastructure/persistence/repositories/drizzle-rbac.repositories';

@Module({
  imports: [
    UserModule,
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
    { provide: 'IRoleRepository', useClass: DrizzleRoleRepository },
    { provide: 'IPermissionRepository', useClass: DrizzlePermissionRepository },
    { provide: 'IUserRoleRepository', useClass: DrizzleUserRoleRepository },
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
import { InMemoryEventBus } from '../../core/shared/infrastructure/adapters/in-memory-event-bus.adapter';
import { DrizzleTransactionManager } from '../../core/shared/infrastructure/persistence/drizzle-transaction.manager';
import { DrizzleModule } from '../../database/drizzle.module';

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
    DrizzleModule,
  ],
  providers: [
    {
      provide: 'IEventBus',
      useClass: InMemoryEventBus,
    },
    {
      provide: 'ITransactionManager',
      useClass: DrizzleTransactionManager,
    },
  ],
  exports: [ConfigModule, 'IEventBus', 'ITransactionManager'],
})
export class SharedModule {}
```

## File: src/modules/test/seeders/database.seeder.ts
```
import { Injectable, OnModuleInit, Inject } from '@nestjs/common';
import { DRIZZLE } from '../../../database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../../database/schema';
import { eq } from 'drizzle-orm';
import * as bcrypt from 'bcrypt';
import {
  SystemPermission,
  SystemRole,
} from '../../rbac/domain/constants/rbac.constants';

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  constructor(@Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>) {}

  async onModuleInit() {
    if (process.env.NODE_ENV !== 'development') return;
    console.log('🌱 Seeding database (Drizzle)...');

    await this.seedPermissions();
    await this.seedRoles();
    await this.seedUsers();
    await this.assignPermissionsToRoles();
    await this.assignRolesToUsers();

    console.log('✅ Database seeded successfully!');
  }

  private async seedPermissions() {
    for (const name of Object.values(SystemPermission)) {
      const [res, act] = name.split(':');
      const exists = await this.db.query.permissions.findFirst({
        where: eq(schema.permissions.name, name),
      });
      if (!exists) {
        await this.db.insert(schema.permissions).values({
          name,
          resourceType: res,
          action: act,
          isActive: true,
          description: `System permission: ${name}`,
        });
      }
    }
    console.log(' - Permissions checked');
  }

  private async seedRoles() {
    for (const name of Object.values(SystemRole)) {
      const exists = await this.db.query.roles.findFirst({
        where: eq(schema.roles.name, name),
      });
      if (!exists) {
        await this.db.insert(schema.roles).values({
          name,
          description: `System role: ${name}`,
          isSystem: true,
          isActive: true,
        });
      }
    }
    console.log(' - Roles checked');
  }

  private async seedUsers() {
    const password = await bcrypt.hash('123456', 10);
    const users = [
      {
        username: 'superadmin',
        fullName: 'Super Admin',
        email: 'admin@test.com',
      },
      { username: 'user1', fullName: 'Normal User', email: 'user@test.com' },
    ];

    for (const u of users) {
      const exists = await this.db.query.users.findFirst({
        where: eq(schema.users.username, u.username),
      });
      if (!exists) {
        await this.db.insert(schema.users).values({
          ...u,
          hashedPassword: password,
          isActive: true,
        });
      }
    }
    console.log(' - Users checked');
  }

  private async assignPermissionsToRoles() {
    // 1. Get Admin Role
    const adminRole = await this.db.query.roles.findFirst({
      where: eq(schema.roles.name, SystemRole.SUPER_ADMIN),
    });
    if (!adminRole) return;

    // 2. Get All Permissions
    const allPerms = await this.db.select().from(schema.permissions);

    // 3. Insert into role_permissions (Ignore duplicates)
    for (const perm of allPerms) {
      await this.db
        .insert(schema.rolePermissions)
        .values({ roleId: adminRole.id, permissionId: perm.id })
        .onConflictDoNothing()
        .catch(() => {}); // Catch duplicate key error silently
    }
    console.log(' - Admin permissions assigned');
  }

  private async assignRolesToUsers() {
    const adminUser = await this.db.query.users.findFirst({
      where: eq(schema.users.username, 'superadmin'),
    });
    const adminRole = await this.db.query.roles.findFirst({
      where: eq(schema.roles.name, SystemRole.SUPER_ADMIN),
    });

    if (adminUser && adminRole) {
      await this.db
        .insert(schema.userRoles)
        .values({ userId: adminUser.id, roleId: adminRole.id })
        .onConflictDoNothing();
    }
    console.log(' - Admin role assigned');
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
import { UserModule } from '../user/user.module';
import { RbacModule } from '../rbac/rbac.module'; // Import RBAC
import { DatabaseSeeder } from './seeders/database.seeder';
import { TestController } from './controllers/test.controller';

@Module({
  imports: [
    UserModule,
    RbacModule, // <--- QUAN TRỌNG: Cần thiết cho PermissionGuard
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

## File: src/core/shared/application/ports/event-bus.port.ts
```
import { IDomainEvent } from '../../domain/events/domain-event.interface';

export interface IEventBus {
  publish<T extends IDomainEvent>(event: T): Promise<void>;
  publishAll(events: IDomainEvent[]): Promise<void>;
  subscribe<T extends IDomainEvent>(
    eventName: string,
    handler: (event: T) => Promise<void>,
  ): void;
  unsubscribe(eventName: string, handler: Function): void;
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

## File: src/core/shared/infrastructure/adapters/in-memory-event-bus.adapter.ts
```
import { Injectable, Logger } from '@nestjs/common';
import { IEventBus } from '../../application/ports/event-bus.port'; // ../../ trỏ về src/core/shared
import { IDomainEvent } from '../../domain/events/domain-event.interface';

@Injectable()
export class InMemoryEventBus implements IEventBus {
  private readonly logger = new Logger(InMemoryEventBus.name);
  private handlers = new Map<string, Function[]>();

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    const eventName = event.eventName;
    const handlers = this.handlers.get(eventName);

    if (handlers) {
      this.logger.debug(`Publishing event: ${eventName}`);
      await Promise.all(handlers.map((handler) => handler(event)));
    }
  }

  async publishAll(events: IDomainEvent[]): Promise<void> {
    await Promise.all(events.map((event) => this.publish(event)));
  }

  subscribe<T extends IDomainEvent>(
    eventName: string,
    handler: (event: T) => Promise<void>,
  ): void {
    if (!this.handlers.has(eventName)) {
      this.handlers.set(eventName, []);
    }
    this.handlers.get(eventName)?.push(handler);
  }

  unsubscribe(eventName: string, handler: Function): void {
    const handlers = this.handlers.get(eventName);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }
}
```

## File: src/core/shared/infrastructure/persistence/drizzle-base.repository.ts
```
import { Inject, Injectable } from '@nestjs/common';
import { DRIZZLE } from '../../../../database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../../../database/schema';
import { Transaction } from '../../application/ports/transaction-manager.port';

@Injectable()
export class DrizzleBaseRepository {
  constructor(
    @Inject(DRIZZLE) protected readonly db: NodePgDatabase<typeof schema>,
  ) {}

  // Helper để lấy DB Context
  protected getDb(tx?: Transaction): NodePgDatabase<typeof schema> {
    return tx ? (tx as NodePgDatabase<typeof schema>) : this.db;
  }
}
```

## File: src/core/shared/infrastructure/persistence/drizzle-transaction.manager.ts
```
import { Inject, Injectable } from '@nestjs/common';
import {
  ITransactionManager,
  Transaction,
} from '../../application/ports/transaction-manager.port';
// FIX PATH: 4 cấp ../ để về src, sau đó vào database
import { DRIZZLE } from '../../../../database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../../../database/schema';

@Injectable()
export class DrizzleTransactionManager implements ITransactionManager {
  constructor(@Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>) {}

  async runInTransaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => {
      return work(tx as unknown as Transaction);
    });
  }
}
```

## File: src/core/shared/domain/value-objects/money.vo.ts
```
export class InvalidMoneyException extends Error {
  constructor(message: string) {
    super(message);
  }
}

export class Money {
  constructor(
    private readonly amount: number,
    private readonly currency: string = 'VND',
  ) {
    if (amount < 0) {
      throw new InvalidMoneyException('Amount cannot be negative');
    }
    if (!Number.isInteger(amount)) {
      throw new InvalidMoneyException('Amount must be an integer');
    }
  }

  add(other: Money): Money {
    this.validateSameCurrency(other);
    return new Money(this.amount + other.amount, this.currency);
  }

  subtract(other: Money): Money {
    this.validateSameCurrency(other);
    if (other.amount > this.amount) {
      throw new InvalidMoneyException('Insufficient funds');
    }
    return new Money(this.amount - other.amount, this.currency);
  }

  multiply(factor: number): Money {
    return new Money(Math.round(this.amount * factor), this.currency);
  }

  getAmount(): number {
    return this.amount;
  }

  getCurrency(): string {
    return this.currency;
  }

  equals(other: Money): boolean {
    return this.amount === other.amount && this.currency === other.currency;
  }

  private validateSameCurrency(other: Money): void {
    if (this.currency !== other.currency) {
      throw new InvalidMoneyException('Currencies must match');
    }
  }
}
```

## File: src/core/shared/domain/events/domain-event.interface.ts
```
export interface IDomainEvent {
  readonly aggregateId: string;
  readonly eventName: string;
  readonly occurredAt: Date;
  readonly payload: Record<string, any>;
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
  // Ưu tiên Connection String (Cloud)
  if (process.env.DATABASE_URL) {
    return { url: process.env.DATABASE_URL };
  }

  // Fallback Local
  return {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_NAME || 'rbac_system',
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

## File: src/database/schema/index.ts
```
export * from './users.schema';
export * from './sessions.schema';
export * from './rbac.schema';
```

## File: src/database/schema/users.schema.ts
```
import {
  pgTable,
  bigserial,
  text,
  boolean,
  timestamp,
  jsonb,
} from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  username: text('username').notNull().unique(),
  email: text('email').unique(), // Nullable by default
  hashedPassword: text('hashedPassword'),
  fullName: text('fullName'),
  isActive: boolean('isActive').default(true),
  phoneNumber: text('phoneNumber'),
  avatarUrl: text('avatarUrl'),
  profile: jsonb('profile'),
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
});
```

## File: src/database/schema/sessions.schema.ts
```
import {
  pgTable,
  uuid,
  bigint,
  text,
  timestamp,
  index,
} from 'drizzle-orm/pg-core';

export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: bigint('userId', { mode: 'number' }).notNull(),
    token: text('token').notNull(),
    expiresAt: timestamp('expiresAt', { withTimezone: true }).notNull(),
    ipAddress: text('ipAddress'),
    userAgent: text('userAgent'),
    createdAt: timestamp('createdAt').defaultNow(),
  },
  (table) => {
    return {
      userIdIdx: index('idx_sessions_user_id').on(table.userId),
    };
  },
);
```

## File: src/database/schema/rbac.schema.ts
```
import {
  pgTable,
  serial,
  text,
  boolean,
  timestamp,
  primaryKey,
  bigint,
  integer,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// Permissions
export const permissions = pgTable('permissions', {
  id: serial('id').primaryKey(),
  name: text('name').notNull().unique(),
  description: text('description'),
  resourceType: text('resourceType'),
  action: text('action'),
  attributes: text('attributes').default('*'),
  isActive: boolean('isActive').default(true),
  createdAt: timestamp('createdAt').defaultNow(),
});

// Roles
export const roles = pgTable('roles', {
  id: serial('id').primaryKey(),
  name: text('name').notNull().unique(),
  description: text('description'),
  isActive: boolean('isActive').default(true),
  isSystem: boolean('isSystem').default(false),
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
});

// User Roles (Many-to-Many User-Role)
export const userRoles = pgTable(
  'user_roles',
  {
    userId: bigint('userId', { mode: 'number' }).notNull(),
    roleId: integer('roleId')
      .notNull()
      .references(() => roles.id),
    assignedBy: bigint('assignedBy', { mode: 'number' }),
    expiresAt: timestamp('expiresAt', { withTimezone: true }),
    assignedAt: timestamp('assignedAt').defaultNow(),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.userId, t.roleId] }),
  }),
);

// Role Permissions (Many-to-Many Role-Permission)
export const rolePermissions = pgTable(
  'role_permissions',
  {
    roleId: integer('role_id')
      .notNull()
      .references(() => roles.id),
    permissionId: integer('permission_id')
      .notNull()
      .references(() => permissions.id),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.roleId, t.permissionId] }),
  }),
);

// Relations
export const rolesRelations = relations(roles, ({ many }) => ({
  permissions: many(rolePermissions),
}));

export const permissionsRelations = relations(permissions, ({ many }) => ({
  roles: many(rolePermissions),
}));

export const rolePermissionsRelations = relations(
  rolePermissions,
  ({ one }) => ({
    role: one(roles, {
      fields: [rolePermissions.roleId],
      references: [roles.id],
    }),
    permission: one(permissions, {
      fields: [rolePermissions.permissionId],
      references: [permissions.id],
    }),
  }),
);
```

## File: src/database/drizzle.provider.ts
```
import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { ConfigService } from '@nestjs/config';
import * as schema from './schema';

export const DRIZZLE = 'DRIZZLE_CONNECTION';

export const drizzleProvider = {
  provide: DRIZZLE,
  inject: [ConfigService],
  useFactory: async (configService: ConfigService) => {
    const connectionString = configService.get<string>('database.url');

    // Config cho cả Local và Cloud
    const host = configService.get<string>('database.host');
    const port = configService.get<number>('database.port');
    const user = configService.get<string>('database.username');
    const password = configService.get<string>('database.password');
    const database = configService.get<string>('database.database');

    const poolConfig = connectionString
      ? { connectionString }
      : { host, port, user, password, database };

    const pool = new Pool(poolConfig);

    return drizzle(pool, { schema });
  },
};
```

## File: src/database/drizzle.module.ts
```
import { Module, Global } from '@nestjs/common';
import { drizzleProvider } from './drizzle.provider';
import { ConfigModule } from '@nestjs/config';

@Global()
@Module({
  imports: [ConfigModule],
  providers: [drizzleProvider],
  exports: [drizzleProvider],
})
export class DrizzleModule {}
```

