## File: src/bootstrap/app.module.ts
```
import { Module, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ServeStaticModule } from '@nestjs/serve-static';
import * as path from 'path';

import databaseConfig from '@config/database.config';
import appConfig from '@config/app.config';
import loggingConfig from '@config/logging.config';
import redisConfig from '@config/redis.config';
import eventBusConfig from '@config/event-bus.config';
import dentalConfig from '@config/dental.config';

import { CoreModule } from '@core/core.module';
import { SharedModule } from '@modules/shared/shared.module';
import { DrizzleModule } from '@database/drizzle.module';
import { LoggingModule } from '@modules/logging/logging.module';
import { RedisCacheModule } from '@core/shared/infrastructure/cache/redis-cache.module';
import { RequestLoggingMiddleware } from '@api/middleware/request-logging.middleware';

import { UserModule } from '@modules/user/user.module';
import { AuthModule } from '@modules/auth/auth.module';
import { RbacModule } from '@modules/rbac/rbac.module';
import { TestModule } from '@modules/test/test.module';
import { NotificationModule } from '@modules/notification/notification.module';
import { DentalModule } from '@modules/dental/dental.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      load: [
        databaseConfig,
        appConfig,
        loggingConfig,
        redisConfig,
        eventBusConfig,
        dentalConfig,
      ],
    }),

    ServeStaticModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => [
        {
          rootPath: path.resolve(
            config.get('dental.outputDir') || 'uploads/dental/converted',
          ),
          serveRoot: '/models',
          exclude: ['/api/(.*)'],
          serveStaticOptions: {
            setHeaders: (res) => {
              res.setHeader('Access-Control-Allow-Origin', '*');
              res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
            },
          },
        },
      ],
      inject: [ConfigService],
    }),

    CoreModule,
    SharedModule,
    DrizzleModule,
    LoggingModule.forRootAsync(),
    RedisCacheModule,

    UserModule,
    AuthModule,
    RbacModule,
    NotificationModule,
    DentalModule,
    TestModule,
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(RequestLoggingMiddleware)
      .forRoutes({ path: '{*path}', method: RequestMethod.ALL });
  }
}
```

## File: src/bootstrap/main.ts
```
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import * as fs from 'fs';

async function bootstrap() {
  const uploadDir = 'uploads/dental/converted';
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  const config = app.get(ConfigService);
  const logger = app.get(LOGGER_TOKEN);
  app.useLogger(logger);

  const prefix: string = config.get('app.apiPrefix', 'api');
  app.setGlobalPrefix(prefix);

  app.enableCors({
    origin: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,
  });

  const swaggerConfig = new DocumentBuilder()
    .setTitle('RBAC System API')
    .setDescription('The RBAC System API description')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: { persistAuthorization: true },
  });

  const port: number = config.get('app.port', 8080);
  await app.listen(port);

  logger.info(`🚀 API is running on: http://localhost:${port}/${prefix}`, {
    context: 'Bootstrap',
  });
  logger.info(`📂 Static Files on:   http://localhost:${port}/models`, {
    context: 'Bootstrap',
  });
}

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

## File: src/modules/auth/domain/repositories/session.repository.ts
```
import { Session } from '../entities/session.entity';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export const ISessionRepository = Symbol('ISessionRepository');

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
import { IUserRepository } from '@modules/user/domain/repositories/user.repository';
import { ISessionRepository } from '../../domain/repositories/session.repository';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { PasswordUtil } from '@core/shared/utils/password.util';
import { User } from '@modules/user/domain/entities/user.entity';
import { Session } from '../../domain/entities/session.entity';
import { JwtPayload } from '@core/shared/types/common.types';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { UserCreatedEvent } from '@modules/user/domain/events/user-created.event';
import {
  type ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';
import { RegisterDto } from '../../infrastructure/dtos/auth.dto';

export type AuthResponse = {
  accessToken: string;
  user: ReturnType<User['toJSON']>;
};

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject(IUserRepository) private userRepository: IUserRepository,
    @Inject(ISessionRepository) private sessionRepository: ISessionRepository,
    @Inject(ITransactionManager) private txManager: ITransactionManager,
    @Inject(IEventBus) private eventBus: IEventBus,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    private jwtService: JwtService,
  ) {}

  async login(credentials: {
    username: string;
    password: string;
    ip?: string;
    userAgent?: string;
  }): Promise<AuthResponse> {
    const user = await this.userRepository.findByUsername(credentials.username);

    if (!user || !user.isActive)
      throw new UnauthorizedException('Invalid credentials');
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

  async register(data: RegisterDto): Promise<AuthResponse> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) throw new BadRequestException('User already exists');

    const hashedPassword = await PasswordUtil.hash(data.password);

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

    return this.txManager.runInTransaction(async (tx) => {
      const savedUser = await this.userRepository.save(newUser, tx);
      if (!savedUser.id)
        throw new InternalServerErrorException('Failed to generate User ID');

      this.logger.info('Register:::');

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

      // Publish Event inside transaction (or use Outbox pattern for better reliability)
      await this.eventBus.publish(
        new UserCreatedEvent(String(savedUser.id), { user: savedUser }),
      );

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
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // 1. Kiểm tra xem route hiện tại (hoặc class controller) có gắn cờ @Public không
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // 2. Nếu là Public -> Cho qua luôn (return true)
    if (isPublic) {
      return true;
    }

    // 3. Nếu không -> Bắt buộc check Token (gọi logic mặc định của Passport)
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
// FIX IMPORT
import { IUserRepository } from '../../../user/domain/repositories/user.repository';
import { JwtPayload } from '../../../shared/types/common.types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    @Inject(IUserRepository) private userRepository: IUserRepository, // FIX: Symbol
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET') || 'super-secret-key',
    });
  }

  async validate(payload: JwtPayload) {
    const user = await this.userRepository.findById(payload.sub);
    if (!user || !user.isActive) return null;
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
import { sessions } from '@database/schema';

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
      raw.createdAt || undefined,
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
// FIX IMPORT
import { ISessionRepository } from '../../domain/repositories/session.repository';
import { Session } from '../../domain/entities/session.entity';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { sessions } from '@database/schema';
import { SessionMapper } from './mappers/session.mapper';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleSessionRepository
  extends DrizzleBaseRepository
  implements ISessionRepository
{
  async create(session: Session, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    const data = SessionMapper.toPersistence(session);

    if (data.id) {
      await db.insert(sessions).values(data as any);
    } else {
      const { id, ...insertData } = data;
      await db
        .insert(sessions)
        .values(insertData as typeof sessions.$inferInsert);
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
import { ISessionRepository } from './domain/repositories/session.repository';

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
    { provide: ISessionRepository, useClass: DrizzleSessionRepository },
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

## File: src/modules/user/domain/repositories/user.repository.ts
```
import { User } from '../entities/user.entity';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

// 1. Token (Runtime)
export const IUserRepository = Symbol('IUserRepository');

// 2. Interface (Compile-time)
export interface IUserRepository {
  findById(id: number, tx?: Transaction): Promise<User | null>;
  findByUsername(username: string, tx?: Transaction): Promise<User | null>;
  findByEmail(email: string, tx?: Transaction): Promise<User | null>;
  findAllActive(): Promise<User[]>;
  save(user: User, tx?: Transaction): Promise<User>;
  findAll(): Promise<User[]>;
  update(id: number, data: Partial<User>): Promise<User>;
  delete(id: number, tx?: Transaction): Promise<void>;
  exists(id: number, tx?: Transaction): Promise<boolean>;
  count(): Promise<number>;
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

## File: src/modules/user/domain/events/user-created.event.ts
```
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';
import { User } from '../entities/user.entity';

export class UserCreatedEvent implements IDomainEvent {
  readonly eventName = 'UserCreated';
  readonly occurredAt = new Date();
  constructor(
    public readonly aggregateId: string,
    public readonly payload: { user: User },
  ) {}
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
import { IUserRepository } from '../../domain/repositories/user.repository';
import { PasswordUtil } from '../../../shared/utils/password.util';
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
  ) {}

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
```

## File: src/modules/user/infrastructure/persistence/mappers/user.mapper.ts
```
import { InferSelectModel, InferInsertModel } from 'drizzle-orm';
// FIX PATH: 3 dots ../../../
import { User } from '../../../domain/entities/user.entity';
import { users } from '@database/schema';

type UserSelect = InferSelectModel<typeof users>;
type UserInsert = InferInsertModel<typeof users>;

export class UserMapper {
  static toDomain(raw: UserSelect | null): User | null {
    if (!raw) return null;
    return new User(
      raw.id,
      raw.username,
      raw.email || undefined,
      raw.hashedPassword || undefined,
      raw.fullName || undefined,
      raw.isActive ?? true,
      raw.phoneNumber || undefined,
      raw.avatarUrl || undefined,
      (raw.profile as any) || undefined,
      raw.createdAt || undefined,
      raw.updatedAt || undefined,
    );
  }

  static toPersistence(domain: User): UserInsert {
    return {
      id: domain.id,
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
// FIX IMPORT: Dùng file mới
import { IUserRepository } from '../../domain/repositories/user.repository';
import { User } from '../../domain/entities/user.entity';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { users } from '@database/schema';
import { UserMapper } from './mappers/user.mapper';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

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
      result = await db
        .update(users)
        .set(data)
        .where(eq(users.id, data.id))
        .returning();
    } else {
      const { id, ...insertData } = data;
      result = await db
        .insert(users)
        .values(insertData as typeof users.$inferInsert)
        .returning();
    }
    return UserMapper.toDomain(result[0])!;
  }

  async findAll(): Promise<User[]> {
    return [];
  }
  async update(): Promise<User> {
    throw new Error('Use save instead');
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
// FIX IMPORT
import { IUserRepository } from './domain/repositories/user.repository';

@Module({
  imports: [],
  controllers: [UserController],
  providers: [
    UserService,
    {
      provide: IUserRepository, // FIX: Dùng Symbol
      useClass: DrizzleUserRepository,
    },
  ],
  exports: [UserService, IUserRepository], // FIX: Export Symbol
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

## File: src/modules/rbac/domain/repositories/rbac.repository.ts
```
import { Role } from '../entities/role.entity';
import { Permission } from '../entities/permission.entity';
import { UserRole } from '../entities/user-role.entity';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

// 1. Role Repository
export const IRoleRepository = Symbol('IRoleRepository');
export interface IRoleRepository {
  findByName(name: string, tx?: Transaction): Promise<Role | null>;
  save(role: Role, tx?: Transaction): Promise<Role>;
  findAllWithPermissions(roleIds: number[], tx?: Transaction): Promise<Role[]>;
  findAll(tx?: Transaction): Promise<Role[]>;
}

// 2. Permission Repository
export const IPermissionRepository = Symbol('IPermissionRepository');
export interface IPermissionRepository {
  findByName(name: string, tx?: Transaction): Promise<Permission | null>;
  save(permission: Permission, tx?: Transaction): Promise<Permission>;
  findAll(tx?: Transaction): Promise<Permission[]>;
}

// 3. User Role Repository
export const IUserRoleRepository = Symbol('IUserRoleRepository');
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
import {
  IUserRoleRepository,
  IRoleRepository,
} from '../../domain/repositories/rbac.repository';
// IMPORT Interface
import { ICacheService } from '@core/shared/application/ports/cache.port';

@Injectable()
export class PermissionService {
  private readonly CACHE_TTL = 300; // Fallback nếu không truyền vào set()
  private readonly CACHE_PREFIX = 'rbac:permissions:';

  constructor(
    @Inject(IUserRoleRepository) private userRoleRepo: IUserRoleRepository,
    @Inject(IRoleRepository) private roleRepo: IRoleRepository,
    @Inject(ICacheService) private cacheService: ICacheService, // ✅ Inject Token
  ) {}

  async userHasPermission(
    userId: number,
    permissionName: string,
  ): Promise<boolean> {
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;

    // Sử dụng abstraction layer
    const cached = await this.cacheService.get<string[]>(cacheKey);

    if (cached) return cached.includes(permissionName) || cached.includes('*');

    const userRoles = await this.userRoleRepo.findByUserId(userId);
    const activeRoles = userRoles.filter(
      (ur) => ur.isActive() && ur.role?.isActive,
    );
    if (activeRoles.length === 0) return false;

    const roleIds = activeRoles.map((ur) => ur.roleId);
    const roles = await this.roleRepo.findAllWithPermissions(roleIds);

    const permissions = new Set<string>();
    roles.forEach((r) =>
      r.permissions?.forEach((p) => {
        if (p.isActive) permissions.add(p.name);
      }),
    );

    const permArray = Array.from(permissions);

    // Cache result
    await this.cacheService.set(cacheKey, permArray);
    // Mặc định adapter sẽ lấy TTL từ config nếu không truyền,
    // hoặc bạn có thể truyền this.CACHE_TTL vào tham số thứ 3

    return permArray.includes(permissionName);
  }

  async assignRole(
    userId: number,
    roleId: number,
    assignedBy: number,
  ): Promise<void> {
    const existing = await this.userRoleRepo.findOne(userId, roleId);
    if (!existing) {
      const userRole: any = {
        userId,
        roleId,
        assignedBy,
        assignedAt: new Date(),
      };
      await this.userRoleRepo.save(userRole);

      // Invalidate cache
      await this.cacheService.del(`${this.CACHE_PREFIX}${userId}`);
    }
  }
}
```

## File: src/modules/rbac/application/services/role.service.ts
```
import { Injectable, Inject } from '@nestjs/common';
import {
  IRoleRepository,
  IPermissionRepository,
} from '../../domain/repositories/rbac.repository';
import { Role } from '../../domain/entities/role.entity';

export interface CreateRoleParams {
  name: string;
  description?: string;
  isSystem?: boolean;
}

export interface AccessControlItem {
  role: string;
  resource: string;
  action: string;
  attributes: string;
}

@Injectable()
export class RoleService {
  constructor(
    @Inject(IRoleRepository) private roleRepo: IRoleRepository,
    @Inject(IPermissionRepository) private permRepo: IPermissionRepository,
  ) {}

  async createRole(data: CreateRoleParams): Promise<Role> {
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

  async findAllRoles(): Promise<Role[]> {
    return this.roleRepo.findAll();
  }

  async getAccessControlList(): Promise<AccessControlItem[]> {
    const roles = await this.roleRepo.findAll();
    const acl: AccessControlItem[] = [];
    roles.forEach((role) => {
      if (role.permissions) {
        role.permissions.forEach((p) => {
          acl.push({
            role: role.name.toLowerCase(),
            resource: p.resourceType || '*',
            action: p.action || '*',
            attributes: p.attributes,
          });
        });
      }
    });
    return acl;
  }
}
```

## File: src/modules/rbac/application/services/rbac-manager.service.ts
```
import { Injectable, Inject, Logger } from '@nestjs/common';
import {
  IRoleRepository,
  IPermissionRepository,
} from '../../domain/repositories/rbac.repository';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';
import { IFileParser } from '@core/shared/application/ports/file-parser.port';

// Helper type for CSV Row
type RbacCsvRow = {
  role: string;
  resource: string;
  action: string;
  attributes: string;
  description: string;
};

@Injectable()
export class RbacManagerService {
  private readonly logger = new Logger(RbacManagerService.name);

  constructor(
    @Inject(IRoleRepository) private roleRepo: IRoleRepository,
    @Inject(IPermissionRepository) private permRepo: IPermissionRepository,
    @Inject(IFileParser) private fileParser: IFileParser, // Injected Parser
  ) {}

  async importFromCsv(csvContent: string): Promise<any> {
    // Sử dụng Adapter để parse (Implementation nên dùng thư viện csv-parse)
    // Hiện tại adapter đang simple split, nhưng service đã decouple
    let lines = csvContent.split(/\r?\n/).filter((line) => line.trim() !== '');
    if (lines.length > 0 && lines[0].toLowerCase().includes('role')) {
      lines.shift();
    }

    let createdCount = 0;
    let updatedCount = 0;

    for (const line of lines) {
      const cols = line.split(',').map((c) => c.trim());
      if (cols.length < 3) continue;

      const [roleName, resource, action, attributes, description] = cols;
      const permName =
        resource === '*' ? 'manage:all' : `${resource}:${action}`;

      let perm = await this.permRepo.findByName(permName);
      if (!perm) {
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
      }

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

      if (!role.permissions) role.permissions = [];
      const hasPerm = role.permissions.some((p) => p.name === perm!.name);

      if (!hasPerm) {
        role.permissions.push(perm!);
        await this.roleRepo.save(role);
      }
    }
    return { created: createdCount, updated: updatedCount };
  }

  async exportToCsv(): Promise<string> {
    const roles = await this.roleRepo.findAll();
    const header = 'role,resource,action,attributes,description';
    const lines = [header];

    for (const role of roles) {
      if (!role.permissions || role.permissions.length === 0) {
        lines.push(`${role.name},,,,`);
        continue;
      }
      for (const perm of role.permissions) {
        const resource = perm.resourceType || '*';
        const action = perm.action || '*';
        const attributes = perm.attributes || '*';
        let desc = perm.description || '';
        if (desc.includes(',')) desc = `"${desc}"`;
        lines.push([role.name, resource, action, attributes, desc].join(','));
      }
    }
    return lines.join('\n');
  }
}
```

## File: src/modules/rbac/infrastructure/controllers/role.controller.ts
```
import { Controller, Get, Post, Body, UseGuards, Inject } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
} from '@nestjs/swagger';
import { RoleService } from '../../application/services/role.service';
import { PermissionService } from '../../application/services/permission.service';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../guards/permission.guard';
import { Permissions } from '../decorators/permission.decorator';
import { RoleResponseDto } from '../dtos/role.dto';
import { AssignRoleDto } from '../dtos/assign-role.dto';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import type { ILogger } from '@core/shared/application/ports/logger.port';

@ApiTags('RBAC - Roles')
@ApiBearerAuth()
@Controller('rbac/roles')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class RoleController {
  constructor(
    private roleService: RoleService,
    private permissionService: PermissionService,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  @ApiOperation({ summary: 'Get all roles with permissions' })
  @ApiResponse({
    status: 200,
    description: 'List of roles',
    type: [RoleResponseDto],
  })
  @Get()
  @Permissions('rbac:manage')
  async getAllRoles(): Promise<RoleResponseDto[]> {
    const roles = await this.roleService.findAllRoles();
    return roles.map((role) => RoleResponseDto.fromDomain(role));
  }

  @ApiOperation({ summary: 'Assign role to user' })
  @Post('assign')
  @Permissions('rbac:manage')
  async assignRole(@Body() dto: AssignRoleDto) {
    await this.permissionService.assignRole(dto.userId, dto.roleId, 1);
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
import { BypassTransform } from '@core/decorators/bypass-transform.decorator';

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
import { InferSelectModel, InferInsertModel } from 'drizzle-orm';
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';
import { roles, permissions, userRoles } from '@database/schema'; // Alias

type RoleSelect = InferSelectModel<typeof roles>;
type PermissionSelect = InferSelectModel<typeof permissions>;
type UserRoleSelect = InferSelectModel<typeof userRoles>;

type RoleWithRelations = RoleSelect & {
  permissions: { permission: PermissionSelect }[];
};

type UserRoleWithRole = UserRoleSelect & {
  role: RoleSelect;
};

export class RbacMapper {
  static toPermissionDomain(raw: PermissionSelect | null): Permission | null {
    if (!raw) return null;
    return new Permission(
      raw.id,
      raw.name,
      raw.description || undefined,
      raw.resourceType || undefined,
      raw.action || undefined,
      raw.isActive ?? true,
      raw.attributes || '*',
      raw.createdAt || undefined,
    );
  }

  static toPermissionPersistence(
    domain: Permission,
  ): InferInsertModel<typeof permissions> {
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

  static toRoleDomain(raw: RoleWithRelations | RoleSelect | null): Role | null {
    if (!raw) return null;
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
      raw.isActive ?? true,
      raw.isSystem ?? false,
      perms,
      raw.createdAt || undefined,
      raw.updatedAt || undefined,
    );
  }

  static toRolePersistence(domain: Role): InferInsertModel<typeof roles> {
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

  static toUserRoleDomain(
    raw: UserRoleWithRole | UserRoleSelect | null,
  ): UserRole | null {
    if (!raw) return null;
    let roleDomain;
    if ('role' in raw && raw.role) {
      roleDomain = new Role(
        raw.role.id,
        raw.role.name,
        raw.role.description || undefined,
      );
    }
    return new UserRole(
      Number(raw.userId),
      raw.roleId,
      raw.assignedBy ? Number(raw.assignedBy) : undefined,
      raw.expiresAt || undefined,
      raw.assignedAt || undefined,
      roleDomain,
    );
  }

  static toUserRolePersistence(
    domain: UserRole,
  ): InferInsertModel<typeof userRoles> {
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
// FIX IMPORT
import {
  IRoleRepository,
  IPermissionRepository,
  IUserRoleRepository,
} from '../../../domain/repositories/rbac.repository';
import { Role } from '../../../domain/entities/role.entity';
import { Permission } from '../../../domain/entities/permission.entity';
import { UserRole } from '../../../domain/entities/user-role.entity';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  roles,
  permissions,
  userRoles,
  rolePermissions,
} from '@database/schema';
import { RbacMapper } from '../mappers/rbac.mapper';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleRoleRepository
  extends DrizzleBaseRepository
  implements IRoleRepository
{
  async findByName(name: string, tx?: Transaction): Promise<Role | null> {
    const db = this.getDb(tx);
    const result = await db.query.roles.findFirst({
      where: eq(roles.name, name),
      with: { permissions: { with: { permission: true } } },
    });
    return result ? RbacMapper.toRoleDomain(result as any) : null;
  }

  async save(role: Role, tx?: Transaction): Promise<Role> {
    const db = this.getDb(tx);
    const data = RbacMapper.toRolePersistence(role);

    return await db.transaction(async (trx) => {
      let savedRoleId: number;
      if (data.id) {
        await trx.update(roles).set(data).where(eq(roles.id, data.id));
        savedRoleId = data.id;
      } else {
        const { id, ...insertData } = data;
        const res = await trx
          .insert(roles)
          .values(insertData as typeof roles.$inferInsert)
          .returning({ id: roles.id });
        savedRoleId = res[0].id;
      }

      if (role.permissions && role.permissions.length > 0) {
        await trx
          .delete(rolePermissions)
          .where(eq(rolePermissions.roleId, savedRoleId));
        const permInserts = role.permissions.map((p) => ({
          roleId: savedRoleId,
          permissionId: p.id!,
        }));
        if (permInserts.length > 0)
          await trx.insert(rolePermissions).values(permInserts);
      }

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
    return result[0] ? RbacMapper.toPermissionDomain(result[0]) : null;
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
      result = await db
        .insert(permissions)
        .values(insertData as typeof permissions.$inferInsert)
        .returning();
    }
    return RbacMapper.toPermissionDomain(result[0])!;
  }

  async findAll(tx?: Transaction): Promise<Permission[]> {
    const db = this.getDb(tx);
    const results = await db.select().from(permissions);
    return results.map((r) => RbacMapper.toPermissionDomain(r)!);
  }
}

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
    await db
      .insert(userRoles)
      .values(data as typeof userRoles.$inferInsert)
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

## File: src/modules/rbac/infrastructure/dtos/role.dto.ts
```
import { ApiProperty } from '@nestjs/swagger';
// FIX PATH: Chỉ cần 2 cấp ../
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';

export class PermissionDto {
  @ApiProperty({ example: 1 })
  id: number;

  @ApiProperty({ example: 'user:create' })
  name: string;

  @ApiProperty({ example: 'Create new users' })
  description: string;

  @ApiProperty({ example: 'user' })
  resourceType: string;

  @ApiProperty({ example: 'create' })
  action: string;
}

export class RoleResponseDto {
  @ApiProperty({ example: 1 })
  id: number;

  @ApiProperty({ example: 'ADMIN' })
  name: string;

  @ApiProperty({ example: 'Administrator with full access' })
  description: string;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({ example: false })
  isSystem: boolean;

  @ApiProperty({ type: [PermissionDto] })
  permissions: PermissionDto[];

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;

  static fromDomain(role: Role): RoleResponseDto {
    const dto = new RoleResponseDto();
    dto.id = role.id!;
    dto.name = role.name;
    dto.description = role.description || '';
    dto.isActive = role.isActive;
    dto.isSystem = role.isSystem;
    dto.createdAt = role.createdAt || new Date();
    dto.updatedAt = role.updatedAt || new Date();

    dto.permissions = role.permissions
      ? role.permissions.map((p) => ({
          id: p.id!,
          name: p.name,
          description: p.description || '',
          resourceType: p.resourceType || '',
          action: p.action || '',
        }))
      : [];

    return dto;
  }
}
```

## File: src/modules/rbac/infrastructure/dtos/assign-role.dto.ts
```
import { ApiProperty } from '@nestjs/swagger';
import { IsNumber } from 'class-validator';

export class AssignRoleDto {
  @ApiProperty({ example: 1005, description: 'User ID' })
  @IsNumber()
  userId: number;

  @ApiProperty({ example: 2, description: 'Role ID' })
  @IsNumber()
  roleId: number;
}
```

## File: src/modules/rbac/rbac.module.ts
```
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { UserModule } from '../user/user.module';
import { RoleController } from './infrastructure/controllers/role.controller';
import { RbacManagerController } from './infrastructure/controllers/rbac-manager.controller';
import { PermissionService } from './application/services/permission.service';
import { RoleService } from './application/services/role.service';
import { RbacManagerService } from './application/services/rbac-manager.service';
import { PermissionGuard } from './infrastructure/guards/permission.guard';
import {
  DrizzleRoleRepository,
  DrizzlePermissionRepository,
  DrizzleUserRoleRepository,
} from './infrastructure/persistence/repositories/drizzle-rbac.repositories';
import {
  IRoleRepository,
  IPermissionRepository,
  IUserRoleRepository,
} from './domain/repositories/rbac.repository';

@Module({
  imports: [
    UserModule,
    // Không cần import CacheModule nữa vì RedisCacheModule là Global
  ],
  controllers: [RoleController, RbacManagerController],
  providers: [
    PermissionService,
    RoleService,
    PermissionGuard,
    RbacManagerService,
    { provide: IRoleRepository, useClass: DrizzleRoleRepository },
    { provide: IPermissionRepository, useClass: DrizzlePermissionRepository },
    { provide: IUserRoleRepository, useClass: DrizzleUserRoleRepository },
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
import { DrizzleTransactionManager } from '@core/shared/infrastructure/persistence/drizzle-transaction.manager';
import { DrizzleModule } from '@database/drizzle.module';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { EventBusModule } from '@core/shared/infrastructure/event-bus/event-bus.module';
import { CsvParserAdapter } from '@core/shared/infrastructure/adapters/csv-parser.adapter';
import { IFileParser } from '@core/shared/application/ports/file-parser.port';

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
    DrizzleModule,
    EventBusModule,
  ],
  providers: [
    {
      provide: ITransactionManager,
      useClass: DrizzleTransactionManager,
    },
    {
      provide: IFileParser,
      useClass: CsvParserAdapter,
    },
  ],
  exports: [ConfigModule, ITransactionManager, EventBusModule, IFileParser],
})
export class SharedModule {}
```

## File: src/modules/test/seeders/database.seeder.ts
```
import { Injectable, OnModuleInit, Inject } from '@nestjs/common';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
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
import { Controller, Get, Inject, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../../rbac/infrastructure/guards/permission.guard';
import { Permissions } from '../../rbac/infrastructure/decorators/permission.decorator';
import { Public } from '../../auth/infrastructure/decorators/public.decorator';
import { CurrentUser } from '../../auth/infrastructure/decorators/current-user.decorator';
import { ApiBearerAuth } from '@nestjs/swagger';
import type { ILogger } from '@core/shared/application/ports/logger.port';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';

@Controller('test')
@ApiBearerAuth()
export class TestController {
  constructor(@Inject(LOGGER_TOKEN) private readonly logger: ILogger) {}

  @Public()
  @Get('health')
  healthCheck() {
    this.logger.info('ciquan');
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

## File: src/modules/logging/infrastructure/winston/winston.factory.ts
```
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as winston from 'winston';

// FIX: Dùng require để tránh lỗi "is not a constructor" do xung đột ES Module/CommonJS
// eslint-disable-next-line @typescript-eslint/no-var-requires
const DailyRotateFile = require('winston-daily-rotate-file');

@Injectable()
export class WinstonFactory {
  constructor(private configService: ConfigService) {}

  createLogger(): winston.Logger {
    const logLevel = this.configService.get('logging.level') || 'info';
    const appName = this.configService.get('app.name') || 'SERVER';
    const isProduction = process.env.NODE_ENV === 'production';

    // 1. MASKER
    const sensitiveKeys = [
      'password',
      'token',
      'authorization',
      'secret',
      'creditCard',
      'cvv',
    ];
    const masker = winston.format((info) => {
      const maskDeep = (obj: any) => {
        if (!obj || typeof obj !== 'object') return;
        Object.keys(obj).forEach((key) => {
          if (sensitiveKeys.some((k) => key.toLowerCase().includes(k))) {
            obj[key] = '***MASKED***';
          } else if (typeof obj[key] === 'object') {
            maskDeep(obj[key]);
          }
        });
      };
      const splat = (info as any)[Symbol.for('splat')];
      if (splat) maskDeep(splat);
      maskDeep(info);
      return info;
    });

    // 2. CONSOLE FORMAT
    const consoleFormat = winston.format.printf((info) => {
      const tsVal = info.timestamp || new Date().toISOString();
      const { level, message, context, requestId, label, timestamp, ...meta } =
        info;

      const cDim = '\x1b[2m';
      const cReset = '\x1b[0m';
      const cCyan = '\x1b[36m';
      const cYellow = '\x1b[33m';

      const splatSymbol = Symbol.for('splat');
      const splat = (info as any)[splatSymbol];
      let finalMeta = { ...meta };
      if (Array.isArray(splat)) {
        const splatObj = splat.find(
          (item: any) => typeof item === 'object' && item !== null,
        );
        if (splatObj) Object.assign(finalMeta, splatObj);
      }

      delete (finalMeta as any).level;
      delete (finalMeta as any).message;
      delete (finalMeta as any).timestamp;
      delete (finalMeta as any).service;

      let metaStr = '';
      if (Object.keys(finalMeta).length) {
        const jsonStr = JSON.stringify(finalMeta);
        if (jsonStr.length < 150) {
          metaStr = ` ${cDim}${jsonStr}${cReset}`;
        } else {
          metaStr = `\n${cDim}${JSON.stringify(finalMeta, null, 2)}${cReset}`;
        }
      }

      const timeDisplay = `${cDim}[${tsVal}]${cReset}`;
      const levelDisplay = level;
      const contextVal = context || label || appName;
      const contextDisplay = `${cYellow}[${contextVal}]${cReset}`;
      const requestDisplay = requestId ? `${cCyan}[${requestId}]${cReset}` : '';

      return `${timeDisplay} ${levelDisplay} ${contextDisplay} ${requestDisplay} ${message}${metaStr}`;
    });

    // 3. TRANSPORTS
    const transports: winston.transport[] = [
      new DailyRotateFile({
        dirname: 'logs',
        filename: 'app-%DATE%.info.log',
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '14d',
        level: 'info',
        format: winston.format.combine(
          winston.format.timestamp(),
          masker(),
          winston.format.json(),
        ),
      }),
      new DailyRotateFile({
        dirname: 'logs',
        filename: 'app-%DATE%.error.log',
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '30d',
        level: 'error',
        format: winston.format.combine(
          winston.format.timestamp(),
          masker(),
          winston.format.json(),
        ),
      }),
    ];

    if (isProduction) {
      transports.push(
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.timestamp(),
            masker(),
            winston.format.json(),
          ),
        }),
      );
    } else {
      transports.push(
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
            masker(),
            winston.format.colorize({ all: true }),
            consoleFormat,
          ),
        }),
      );
    }

    return winston.createLogger({
      level: logLevel,
      defaultMeta: { service: appName },
      transports,
      exitOnError: false,
    });
  }
}
```

## File: src/modules/logging/infrastructure/winston/winston-logger.adapter.ts
```
import { Injectable, Inject, LoggerService } from '@nestjs/common';
import * as winston from 'winston';
import {
  ILogger,
  LogContext,
} from '@core/shared/application/ports/logger.port';
import { RequestContextService } from '@core/shared/infrastructure/context/request-context.service';

@Injectable()
export class WinstonLoggerAdapter implements ILogger, LoggerService {
  private context: LogContext = {};

  constructor(
    @Inject('WINSTON_LOGGER') private readonly winstonLogger: winston.Logger,
  ) {}

  private getTraceInfo() {
    return {
      requestId: RequestContextService.getRequestId(),
    };
  }

  // --- Helper để chuẩn hóa tham số từ NestJS Core ---
  private normalizeParams(message: any, ...optionalParams: any[]) {
    let contextObj: LogContext = {};

    // Xử lý trường hợp NestJS gửi context là string ở tham số cuối
    if (optionalParams.length > 0) {
      const lastParam = optionalParams[optionalParams.length - 1];
      if (typeof lastParam === 'string') {
        contextObj.context = lastParam; // Gán vào field context
        // Bỏ string context ra khỏi params để không bị trùng
        // optionalParams.pop();
      } else if (typeof lastParam === 'object') {
        contextObj = { ...lastParam };
      }
    }

    // Nếu message là object (NestJS hay log object), stringify nó hoặc gán vào meta
    const msgStr =
      typeof message === 'string' ? message : JSON.stringify(message);

    return { msgStr, contextObj };
  }

  // --- Implementation cho LoggerService (NestJS Core gọi cái này) ---

  log(message: any, ...optionalParams: any[]) {
    // Map 'log' của Nest sang 'info' của Winston
    this.info(message, ...optionalParams);
  }

  // --- Implementation cho ILogger (App của ta gọi cái này) ---

  debug(message: any, ...optionalParams: any[]): void {
    const { msgStr, contextObj } = this.normalizeParams(
      message,
      ...optionalParams,
    );
    this.callWinston('debug', msgStr, contextObj);
  }

  info(message: any, ...optionalParams: any[]): void {
    const { msgStr, contextObj } = this.normalizeParams(
      message,
      ...optionalParams,
    );
    this.callWinston('info', msgStr, contextObj);
  }

  warn(message: any, ...optionalParams: any[]): void {
    const { msgStr, contextObj } = this.normalizeParams(
      message,
      ...optionalParams,
    );
    this.callWinston('warn', msgStr, contextObj);
  }

  error(message: any, ...optionalParams: any[]): void {
    // NestJS thường gửi stack trace ở tham số thứ 2 hoặc 3
    const { msgStr, contextObj } = this.normalizeParams(
      message,
      ...optionalParams,
    );

    // Tìm Error object nếu có trong params
    const errorObj = optionalParams.find((p) => p instanceof Error);
    const meta = { ...contextObj };

    if (errorObj) {
      meta.stack = errorObj.stack;
      meta.error = errorObj.message;
    }

    this.callWinston('error', msgStr, meta);
  }

  // --- Context Methods ---

  withContext(context: LogContext): ILogger {
    const child = new WinstonLoggerAdapter(this.winstonLogger);
    child.context = { ...this.context, ...context };
    return child;
  }

  createChildLogger(module: string): ILogger {
    return this.withContext({ context: module }); // Map 'label' hoặc 'context' tùy config winston
  }

  private callWinston(
    level: string,
    message: string,
    context?: LogContext,
  ): void {
    this.winstonLogger.log(level, message, {
      ...this.context,
      ...this.getTraceInfo(),
      ...context,
    });
  }
}
```

## File: src/modules/logging/logging.module.ts
```
import { Module, DynamicModule, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { WinstonFactory } from './infrastructure/winston/winston.factory';
import { WinstonLoggerAdapter } from './infrastructure/winston/winston-logger.adapter';
// Import Token
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';

@Global()
@Module({})
export class LoggingModule {
  static forRootAsync(): DynamicModule {
    return {
      module: LoggingModule,
      imports: [ConfigModule],
      providers: [
        WinstonFactory,
        {
          provide: 'WINSTON_LOGGER', // Cái này nội bộ module, để string cũng tạm được
          useFactory: (factory: WinstonFactory) => factory.createLogger(),
          inject: [WinstonFactory],
        },
        {
          provide: LOGGER_TOKEN, // ✅ Dùng Token Constant
          useClass: WinstonLoggerAdapter,
        },
      ],
      exports: [LOGGER_TOKEN], // ✅ Export bằng Token
    };
  }
}
```

## File: src/modules/notification/domain/entities/notification.entity.ts
```
import {
  NotificationType,
  NotificationStatus,
} from '../enums/notification.enum';

export class Notification {
  constructor(
    public id: number | undefined,
    public userId: number,
    public type: NotificationType,
    public subject: string,
    public content: string,
    public status: NotificationStatus = NotificationStatus.PENDING,
    public sentAt?: Date,
    public createdAt?: Date,
  ) {}

  markAsSent() {
    this.status = NotificationStatus.SENT;
    this.sentAt = new Date();
  }

  markAsFailed() {
    this.status = NotificationStatus.FAILED;
  }
}
```

## File: src/modules/notification/domain/repositories/notification.repository.ts
```
import { Notification } from '../entities/notification.entity';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export const INotificationRepository = Symbol('INotificationRepository');

export interface INotificationRepository {
  save(notification: Notification, tx?: Transaction): Promise<Notification>;
  findByUserId(userId: number): Promise<Notification[]>;
}
```

## File: src/modules/notification/domain/enums/notification.enum.ts
```
export enum NotificationType {
  EMAIL = 'EMAIL',
  SMS = 'SMS',
  PUSH = 'PUSH',
}

export enum NotificationStatus {
  PENDING = 'PENDING',
  SENT = 'SENT',
  FAILED = 'FAILED',
}
```

## File: src/modules/notification/application/services/notification.service.ts
```
import { Injectable, Inject } from '@nestjs/common';
import { INotificationRepository } from '../../domain/repositories/notification.repository';
import { IEmailSender } from '../ports/email-sender.port';
import { Notification } from '../../domain/entities/notification.entity';
import { NotificationType } from '../../domain/enums/notification.enum';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';

@Injectable()
export class NotificationService {
  constructor(
    @Inject(INotificationRepository)
    private readonly repo: INotificationRepository,
    @Inject(IEmailSender) private readonly emailSender: IEmailSender,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  async sendWelcomeEmail(
    userId: number,
    email: string,
    username: string,
  ): Promise<void> {
    this.logger.info(`Processing welcome email for user: ${userId}`);

    // 1. Tạo Entity (Pending)
    const notification = new Notification(
      undefined,
      userId,
      NotificationType.EMAIL,
      'Welcome to RBAC System',
      `Hello ${username}, welcome aboard!`,
    );

    // 2. Lưu vào DB
    const savedNotif = await this.repo.save(notification);

    // 3. Gửi Email thật (qua Adapter)
    const sent = await this.emailSender.send(
      email,
      savedNotif.subject,
      savedNotif.content,
    );

    // 4. Update trạng thái
    if (sent) {
      savedNotif.markAsSent();
    } else {
      savedNotif.markAsFailed();
    }

    await this.repo.save(savedNotif);
    this.logger.info(`Notification processed. Status: ${savedNotif.status}`);
  }

  async getUserNotifications(userId: number) {
    this.logger.info('user::', { userId });
    return this.repo.findByUserId(userId);
  }
}
```

## File: src/modules/notification/application/listeners/user-registered.listener.ts
```
import { Injectable } from '@nestjs/common';
import { EventHandler } from '@core/shared/infrastructure/event-bus/decorators/event-handler.decorator';
import { UserCreatedEvent } from '@modules/user/domain/events/user-created.event';
import { NotificationService } from '../services/notification.service';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';
import { Inject } from '@nestjs/common';

@Injectable()
export class UserRegisteredListener {
  constructor(
    private readonly notificationService: NotificationService,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  @EventHandler(UserCreatedEvent)
  async handleUserCreated(event: UserCreatedEvent) {
    const { user } = event.payload;
    this.logger.info(
      `📢 [EVENT RECEIVED] UserCreated: ${user.username} (ID: ${user.id})`,
    );

    // Gọi Service để xử lý nghiệp vụ
    if (user.email && user.id) {
      await this.notificationService.sendWelcomeEmail(
        user.id,
        user.email,
        user.username,
      );
    }
  }
}
```

## File: src/modules/notification/application/ports/email-sender.port.ts
```
export const IEmailSender = Symbol('IEmailSender');

export interface IEmailSender {
  send(to: string, subject: string, body: string): Promise<boolean>;
}
```

## File: src/modules/notification/infrastructure/persistence/mappers/notification.mapper.ts
```
import { InferSelectModel, InferInsertModel } from 'drizzle-orm';
import { Notification } from '../../../domain/entities/notification.entity';
import {
  NotificationType,
  NotificationStatus,
} from '../../../domain/enums/notification.enum';
import { notifications } from '@database/schema';

type NotificationSelect = InferSelectModel<typeof notifications>;
type NotificationInsert = InferInsertModel<typeof notifications>;

export class NotificationMapper {
  static toDomain(raw: NotificationSelect | null): Notification | null {
    if (!raw) return null;
    return new Notification(
      raw.id,
      raw.userId,
      raw.type as NotificationType,
      raw.subject,
      raw.content,
      raw.status as NotificationStatus,
      raw.sentAt || undefined,
      raw.createdAt || undefined,
    );
  }

  static toPersistence(domain: Notification): NotificationInsert {
    return {
      id: domain.id,
      userId: domain.userId,
      type: domain.type,
      subject: domain.subject,
      content: domain.content,
      status: domain.status,
      sentAt: domain.sentAt || null,
      createdAt: domain.createdAt || new Date(),
    };
  }
}
```

## File: src/modules/notification/infrastructure/persistence/drizzle-notification.repository.ts
```
import { Inject, Injectable } from '@nestjs/common';
import { eq, desc, InferSelectModel } from 'drizzle-orm'; // 1. Import InferSelectModel
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { DRIZZLE } from '@database/drizzle.provider';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';
import { INotificationRepository } from '../../domain/repositories/notification.repository';
import { Notification } from '../../domain/entities/notification.entity';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { notifications } from '@database/schema';
import { NotificationMapper } from './mappers/notification.mapper';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

// 2. Định nghĩa kiểu trả về từ DB để tránh 'any'
type NotificationRecord = InferSelectModel<typeof notifications>;

@Injectable()
export class DrizzleNotificationRepository
  extends DrizzleBaseRepository
  implements INotificationRepository
{
  constructor(
    @Inject(DRIZZLE) db: NodePgDatabase<typeof schema>,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {
    super(db);
  }

  async save(
    notification: Notification,
    tx?: Transaction,
  ): Promise<Notification> {
    const db = this.getDb(tx);
    const data = NotificationMapper.toPersistence(notification);

    // 3. Khai báo kiểu rõ ràng cho result -> Fix lỗi "Variable implicitly has an 'any' type"
    let result: NotificationRecord[];

    if (data.id) {
      result = await db
        .update(notifications)
        .set(data)
        .where(eq(notifications.id, data.id))
        .returning();
    } else {
      // 4. Fix lỗi "'id' assigned but never used": Đổi tên thành '_id' (quy ước biến không dùng)
      const { id: _id, ...insertData } = data;

      // 5. Fix lỗi "Assertion is unnecessary": Bỏ đoạn 'as typeof ...'
      result = await db.insert(notifications).values(insertData).returning();
    }

    // FIX: Kiểm tra kết quả trả về thay vì dùng '!'
    const mapped = NotificationMapper.toDomain(result[0]);

    // Nếu mapper trả về null (trường hợp hiếm), ném lỗi để crash sớm thay vì trả về null sai type
    if (!mapped) {
      throw new Error('Failed to map notification result from DB');
    }

    return mapped;
  }

  async findByUserId(userId: number): Promise<Notification[]> {
    // 7. Đảm bảo biến userId được sử dụng trong câu query
    const results = await this.db
      .select()
      .from(notifications)
      .where(eq(notifications.userId, userId))
      .orderBy(desc(notifications.createdAt));

    // 8. Format code để fix lỗi Prettier
    // return results.map((r) => NotificationMapper.toDomain(r)!);
    // FIX: Map dữ liệu và lọc bỏ null một cách an toàn (Type Guard)
    return results
      .map((r) => NotificationMapper.toDomain(r))
      .filter((n): n is Notification => n !== null);
  }
}
```

## File: src/modules/notification/infrastructure/adapters/console-email.adapter.ts
```
import { Injectable, Inject } from '@nestjs/common';
import { IEmailSender } from '../../application/ports/email-sender.port';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';

@Injectable()
export class ConsoleEmailAdapter implements IEmailSender {
  constructor(@Inject(LOGGER_TOKEN) private readonly logger: ILogger) {}

  async send(to: string, subject: string, body: string): Promise<boolean> {
    // Giả lập độ trễ mạng
    await new Promise((resolve) => setTimeout(resolve, 500));

    this.logger.info(`📧 [MOCK EMAIL SENT] To: ${to} | Subject: ${subject}`);
    this.logger.debug(`Body: ${body}`);

    return true; // Luôn thành công
  }
}
```

## File: src/modules/notification/infrastructure/controllers/notification.controller.ts
```
import { Controller, Get, Inject, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { User } from '@modules/user/domain/entities/user.entity';
import { NotificationService } from '../../application/services/notification.service';
import {
  type ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';

@ApiTags('Notifications')
@ApiBearerAuth()
@Controller('notifications')
@UseGuards(JwtAuthGuard)
export class NotificationController {
  constructor(
    private readonly service: NotificationService,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  @ApiOperation({ summary: 'Get my notifications' })
  @Get()
  async getMyNotifications(@CurrentUser() user: User) {
    if (!user.id) return [];
    return this.service.getUserNotifications(user.id);
  }
}
```

## File: src/modules/notification/notification.module.ts
```
import { Module } from '@nestjs/common';
import { NotificationService } from './application/services/notification.service';
import { UserRegisteredListener } from './application/listeners/user-registered.listener';
import { NotificationController } from './infrastructure/controllers/notification.controller';
import { DrizzleNotificationRepository } from './infrastructure/persistence/drizzle-notification.repository';
import { INotificationRepository } from './domain/repositories/notification.repository';
import { ConsoleEmailAdapter } from './infrastructure/adapters/console-email.adapter';
import { IEmailSender } from './application/ports/email-sender.port';

@Module({
  controllers: [NotificationController],
  providers: [
    NotificationService,
    UserRegisteredListener, // Đăng ký Listener để EventBus Explorer quét được
    {
      provide: INotificationRepository,
      useClass: DrizzleNotificationRepository,
    },
    {
      provide: IEmailSender,
      useClass: ConsoleEmailAdapter, // Có thể đổi thành SES/SendGridAdapter sau này
    },
  ],
  exports: [NotificationService],
})
export class NotificationModule {}
```

## File: src/modules/dental/application/services/dental.service.ts
```
import { Injectable, Inject, BadRequestException, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Piscina from 'piscina';
import * as fs from 'fs-extra';
import * as path from 'path';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const AdmZip = require('adm-zip');
import { v4 as uuidv4 } from 'uuid';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { PISCINA_POOL } from '../../infrastructure/workers/piscina.provider';
import { IOrthoRepository } from '../../domain/repositories/ortho.repository';
import { UploadCaseDto } from '../../infrastructure/dtos/upload-case.dto';
import { parseMovementExcel } from '../utils/movement.parser';

export interface ModelStep {
  index: number;
  maxillary: string | null;
  mandibular: string | null;
  // ✅ NEW: Thêm trường teethData trả về Frontend
  teethData?: Record<string, any>;
}

@Injectable()
export class DentalService {
  private readonly uploadDir: string;
  private readonly outputDir: string;
  private readonly encryptionKey: string;
  private readonly appUrl: string;

  constructor(
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    @Inject(PISCINA_POOL) private readonly pool: Piscina,
    @Inject(IOrthoRepository) private readonly orthoRepo: IOrthoRepository,
    private readonly config: ConfigService,
  ) {
    const rawUploadDir = this.config.get('dental.uploadDir');
    const rawOutputDir = this.config.get('dental.outputDir');
    this.appUrl = (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, "");

    if (!rawUploadDir || !rawOutputDir) throw new Error('Dental configuration missing');

    this.uploadDir = path.resolve(rawUploadDir);
    this.outputDir = path.resolve(rawOutputDir);
    this.encryptionKey = this.config.get('dental.encryptionKey')!;

    fs.ensureDirSync(this.uploadDir);
    fs.ensureDirSync(this.outputDir);
  }

  // ... (processZipUpload giữ nguyên) ...
  async processZipUpload(file: Express.Multer.File, dto: UploadCaseDto) {
    if (!file) throw new BadRequestException('No file uploaded');

    const caseId = await this.orthoRepo.createFullCase({
        patientName: dto.patientName,
        patientCode: dto.patientCode,
        clinicName: dto.clinicName,
        doctorName: dto.doctorName,
        gender: dto.gender,
        productType: dto.productType,
        notes: dto.notes
    });

    this.logger.info(`Processing upload for PatientCode: ${dto.patientCode} -> CaseID: ${caseId}`);

    const jobId = uuidv4();
    const extractPath = path.join(this.uploadDir, `extract_${jobId}`);

    try {
        const zip = new AdmZip(file.path);
        zip.extractAllTo(extractPath, true);

        const objFiles = await this.findFilesRecursively(extractPath, '.obj');
        // if (objFiles.length === 0) throw new Error("No .obj files found"); // Cho phép upload 0 file nếu chỉ muốn tạo case

        const tasks = objFiles.map(objPath => {
            const baseName = path.basename(objPath, '.obj');
            const parentDirPath = path.dirname(objPath);
            const parentDirName = path.basename(parentDirPath);

            let type: 'Maxillary' | 'Mandibular' = 'Maxillary';
            if (baseName.toLowerCase().includes('mandibular')) type = 'Mandibular';

            let index = 0;
            const explicitFolderMatch = parentDirName.match(/(?:Subsetup|Stage|Step)[^0-9]*(\d+)/i);
            const fileNumberMatch = baseName.match(/[ _-](\d+)$/);

            if (explicitFolderMatch) index = parseInt(explicitFolderMatch[1], 10);
            else if (fileNumberMatch) index = parseInt(fileNumberMatch[1], 10);
            else if (/^\d+$/.test(parentDirName)) index = parseInt(parentDirName, 10);

            const standardizedName = `${type}_${index.toString().padStart(3, '0')}`;
            const targetDir = path.join(this.outputDir, caseId, type);

            return {
                objFilePath: objPath,
                outputDir: targetDir,
                baseName: standardizedName,
                encryptionKey: this.encryptionKey,
                config: {
                    ratio: this.config.get('dental.simplificationRatio'),
                    threshold: this.config.get('dental.errorThreshold'),
                    timeout: this.config.get('dental.timeout'),
                },
                meta: { index, type }
            };
        });

        await Promise.allSettled(tasks.map(t => this.pool.run(t)));
        return { message: 'Processing completed', caseId: caseId, patientCode: dto.patientCode };
    } catch (error: any) {
        this.logger.error(`Error processing case ${caseId}`, error);
        throw new BadRequestException(`Processing failed: ${error.message}`);
    } finally {
        await Promise.all([ fs.remove(extractPath).catch(() => {}), fs.remove(file.path).catch(() => {}) ]);
    }
  }

  // ✅ NEW: Xử lý Upload Excel Movement
  async processMovementExcel(file: Express.Multer.File, caseId: string) {
      this.logger.info(`Processing Movement Excel for Case: ${caseId}`);
      try {
          const stepsDataMap = parseMovementExcel(file.buffer);
          let count = 0;

          // Lưu từng step vào DB
          for (const [stepIndex, teethData] of stepsDataMap.entries()) {
              await this.orthoRepo.updateStepMovementData(caseId, stepIndex, teethData);
              count++;
          }

          this.logger.info(`Updated movement data for ${count} steps.`);
          return { message: 'Movement data updated successfully', stepsCount: count };

      } catch (error: any) {
          this.logger.error(`Excel Parse Error`, error);
          throw new BadRequestException(`Failed to parse excel: ${error.message}`);
      }
  }

  async getCaseDetails(clientIdOrCode: string, specificCaseId?: string) {
      if (specificCaseId) {
           const isValid = await this.orthoRepo.checkCaseBelongsToPatient(specificCaseId, clientIdOrCode);
           if (!isValid) throw new NotFoundException(`Case not found for patient ${clientIdOrCode}`);
           return this.orthoRepo.getCaseDetails(specificCaseId, true);
      } else {
           return this.orthoRepo.getCaseDetails(clientIdOrCode, false);
      }
  }

  // ✅ UPDATED: List Models bao gồm cả Movement Data từ DB
  async listModels(clientIdOrCode: string, specificCaseId?: string): Promise<ModelStep[]> {
      let targetFolder = '';
      let dbCaseId = ''; // ID số trong DB

      if (specificCaseId) {
          const isValid = await this.orthoRepo.checkCaseBelongsToPatient(specificCaseId, clientIdOrCode);
          if (!isValid) throw new NotFoundException(`Case not found for patient ${clientIdOrCode}`);
          targetFolder = specificCaseId;
          dbCaseId = specificCaseId;
      } else {
          const latestCaseId = await this.orthoRepo.findLatestCaseIdByCode(clientIdOrCode);
          if (latestCaseId) {
              targetFolder = latestCaseId;
              dbCaseId = latestCaseId;
          } else if (fs.existsSync(path.join(this.outputDir, clientIdOrCode))) {
              targetFolder = clientIdOrCode;
              // Legacy folder không có trong DB thì không có movement data
          }
      }

      if (!targetFolder) return [];

      // 1. Quét File System để lấy danh sách file 3D
      const clientDir = path.join(this.outputDir, targetFolder);
      const allEncFiles = fs.existsSync(clientDir) ? await this.findFilesRecursively(clientDir, '.enc') : [];

      // 2. Query DB để lấy Movement Data (nếu có CaseID hợp lệ)
      let dbSteps: any[] = [];
      if (dbCaseId && !isNaN(Number(dbCaseId))) {
          dbSteps = await this.orthoRepo.getStepsByCaseId(Number(dbCaseId));
      }

      // 3. Merge Data (File System + DB)
      const stepsMap = new Map<number, ModelStep>();

      // Populate từ DB trước (để lấy teethData)
      dbSteps.forEach(dbStep => {
          if (!stepsMap.has(dbStep.stepIndex)) {
              stepsMap.set(dbStep.stepIndex, {
                  index: dbStep.stepIndex,
                  maxillary: null,
                  mandibular: null,
                  teethData: dbStep.teethData // ✅ Attach Data
              });
          }
      });

      // Populate từ File System (để lấy URL file)
      allEncFiles.forEach(fullPath => {
          const filename = path.basename(fullPath).toLowerCase();
          const relativePath = path.relative(this.outputDir, fullPath);
          const urlPath = relativePath.split(path.sep).map(encodeURIComponent).join('/');
          const url = `${this.appUrl}/models/${urlPath}`;

          let index = 0;
          let type: 'maxillary' | 'mandibular' | null = null;
          if (filename.includes('maxillary')) type = 'maxillary';
          else if (filename.includes('mandibular')) type = 'mandibular';

          if (!type) return;

          const fileMatch = filename.match(/(\d+)/);
          if (fileMatch) index = parseInt(fileMatch[1], 10);

          if (!stepsMap.has(index)) {
              stepsMap.set(index, { index, maxillary: null, mandibular: null });
          }
          const entry = stepsMap.get(index)!;
          if (type === 'maxillary') entry.maxillary = url;
          else entry.mandibular = url;
      });

      return Array.from(stepsMap.values()).sort((a, b) => a.index - b.index);
  }

  async getHistory(patientCode: string) {
      return this.orthoRepo.findCasesByPatientCode(patientCode);
  }

  private async findFilesRecursively(dir: string, ext: string): Promise<string[]> {
    let results: string[] = [];
    try {
        const list = await fs.readdir(dir);
        for (const file of list) {
            const fullPath = path.resolve(dir, file);
            const stat = await fs.stat(fullPath);
            if (stat && stat.isDirectory()) {
                results = results.concat(await this.findFilesRecursively(fullPath, ext));
            } else if (file.toLowerCase().endsWith(ext)) {
                results.push(fullPath);
            }
        }
    } catch (e) { }
    return results;
  }
}
```

## File: src/modules/dental/application/utils/movement.parser.ts
```
import * as XLSX from 'xlsx';
import { BadRequestException } from '@nestjs/common';

// Cấu trúc JSON lưu vào DB
export interface ToothMoveData {
  extrusion: number;
  translationX: number;
  translationY: number;
  rotation: number;
  angulation: number;
  torque: number;
}

export const parseMovementExcel = (buffer: Buffer): Map<number, Record<string, ToothMoveData>> => {
  try {
    const workbook = XLSX.read(buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];

    // Chuyển sang JSON: [[Step, Tooth, Ext...], [1, 11, 0.1...]]
    const jsonData = XLSX.utils.sheet_to_json(sheet) as any[];

    // Map: StepIndex -> { ToothID: Data }
    const stepsMap = new Map<number, Record<string, ToothMoveData>>();

    jsonData.forEach((row) => {
        // Chuẩn hóa key (viết thường, bỏ khoảng trắng) để dễ map
        const cleanRow: any = {};
        Object.keys(row).forEach(k => {
            cleanRow[k.toLowerCase().trim().replace(/_/g, '')] = row[k];
        });

        // Lấy Step và Tooth (bắt buộc)
        const step = parseInt(cleanRow['step'] || cleanRow['stage']);
        const tooth = String(cleanRow['tooth'] || cleanRow['toothid']);

        if (isNaN(step) || !tooth) return;

        if (!stepsMap.has(step)) {
            stepsMap.set(step, {});
        }

        const stepData = stepsMap.get(step)!;

        // Lưu dữ liệu vào object
        stepData[tooth] = {
            extrusion: parseFloat(cleanRow['extrusion'] || 0),
            translationX: parseFloat(cleanRow['translationx'] || cleanRow['transx'] || 0),
            translationY: parseFloat(cleanRow['translationy'] || cleanRow['transy'] || 0),
            rotation: parseFloat(cleanRow['rotation'] || cleanRow['rot'] || 0),
            angulation: parseFloat(cleanRow['angulation'] || cleanRow['ang'] || 0),
            torque: parseFloat(cleanRow['torque'] || cleanRow['tor'] || 0),
        };
    });

    return stepsMap;
  } catch (error: any) {
    throw new BadRequestException('Invalid Excel file format. ' + error.message);
  }
};
```

## File: src/modules/dental/infrastructure/controllers/dental.controller.ts
```
import { Controller, Post, Get, Query, UploadedFile, UseInterceptors, UseGuards, Body } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiTags, ApiConsumes, ApiBody, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { diskStorage } from 'multer';
import * as fs from 'fs-extra';
import { DentalService } from '../../application/services/dental.service';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { UploadCaseDto } from '../dtos/upload-case.dto';
import { Public } from '@modules/auth/infrastructure/decorators/public.decorator';

const uploadDir = 'uploads/temp';
try { fs.ensureDirSync(uploadDir); } catch (e) {}

const storage = diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});

@ApiTags('Dental 3D')
@ApiBearerAuth()
@Controller('dental')
@UseGuards(JwtAuthGuard)
export class DentalController {
  constructor(private readonly dentalService: DentalService) {}

  @Post('upload')
  @ApiConsumes('multipart/form-data')
  @ApiBody({ type: UploadCaseDto })
  @UseInterceptors(FileInterceptor('file', { storage }))
  async uploadZip(
    @UploadedFile() file: Express.Multer.File,
    @Body() dto: UploadCaseDto
  ) {
    return this.dentalService.processZipUpload(file, dto);
  }

  // ✅ NEW: API Upload Excel Data
  @Post('upload-movement')
  @ApiConsumes('multipart/form-data')
  @ApiBody({ schema: { type: 'object', properties: { file: { type: 'string', format: 'binary' }, caseId: { type: 'string' } } } })
  @UseInterceptors(FileInterceptor('file', { storage }))
  async uploadMovement(
    @UploadedFile() file: Express.Multer.File,
    @Body('caseId') caseId: string
  ) {
    return this.dentalService.processMovementExcel(file, caseId);
  }

  @Public()
  @Get('models')
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  @ApiQuery({ name: 'caseId', required: false })
  async listModels(
    @Query('clientId') clientId: string,
    @Query('caseId') caseId?: string
  ) {
      return this.dentalService.listModels(clientId, caseId);
  }

  @Public()
  @Get('case-details')
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  @ApiQuery({ name: 'caseId', required: false })
  async getCaseDetails(
    @Query('clientId') clientId: string,
    @Query('caseId') caseId?: string
  ) {
      return this.dentalService.getCaseDetails(clientId, caseId);
  }

  @Get('history')
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  async getHistory(@Query('clientId') clientId: string) {
      return this.dentalService.getHistory(clientId);
  }
}
```

## File: src/modules/dental/infrastructure/workers/conversion.worker.ts
```
import * as path from 'path';
import * as fs from 'fs-extra';
import { execFile } from 'child_process';
import * as util from 'util';
import * as crypto from 'crypto';
import { pipeline } from 'stream/promises';

const execFilePromise = util.promisify(execFile);

// ==========================================
// 1. CONSTANTS & CONFIG
// ==========================================
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const MAX_SEARCH_DEPTH = 10;

// ==========================================
// 2. CUSTOM EXCEPTIONS
// ==========================================
export class WorkerBaseError extends Error {
  constructor(
    message: string,
    public readonly originalError?: unknown,
  ) {
    super(message);
    this.name = this.constructor.name;
    if (originalError instanceof Error) {
      this.stack += `\nCaused by: ${originalError.stack}`;
    }
  }
}

export class FileSystemError extends WorkerBaseError {}
export class ConversionProcessError extends WorkerBaseError {}
export class EncryptionError extends WorkerBaseError {}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;

  if (typeof error === 'object' && error !== null) {
    try {
      return JSON.stringify(error);
    } catch {
      // ignore
    }
  }
  return String(error as any);
}

// ==========================================
// 3. INTERFACES
// ==========================================
export interface ConversionConfig {
  ratio: number;
  threshold: number;
  timeout: number;
}

export interface ConversionTask {
  objFilePath: string;
  outputDir: string;
  baseName: string;
  encryptionKey: string;
  config: ConversionConfig;
}

export interface WorkerResult {
  success: boolean;
  path: string;
}

interface Binaries {
  obj2gltf: string;
  gltfTransform: string;
  gltfPipeline: string;
}

// ==========================================
// 4. HELPER FUNCTIONS
// ==========================================

function findProjectRoot(startDir: string): string {
  let currentDir = path.resolve(startDir);
  for (let i = 0; i < MAX_SEARCH_DEPTH; i++) {
    if (fs.existsSync(path.join(currentDir, 'package.json'))) {
      return currentDir;
    }
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) break;
    currentDir = parentDir;
  }
  return startDir;
}

function resolveBinaries(): Binaries {
  const projectRoot = findProjectRoot(process.cwd());
  const binPath = path.resolve(projectRoot, 'node_modules', '.bin');
  const isWin = process.platform === 'win32';

  const getBinPath = (cmd: string) =>
    path.join(binPath, isWin ? `${cmd}.cmd` : cmd);

  const bins = {
    obj2gltf: getBinPath('obj2gltf'),
    gltfTransform: getBinPath('gltf-transform'),
    gltfPipeline: getBinPath('gltf-pipeline'),
  };

  if (!fs.existsSync(bins.obj2gltf))
    throw new FileSystemError(`Binary not found: ${bins.obj2gltf}`);

  return bins;
}

async function runCommand(
  bin: string,
  args: string[],
  timeout: number,
): Promise<void> {
  try {
    await execFilePromise(bin, args, { timeout });
  } catch (error: unknown) {
    const cmdName = path.basename(bin);
    throw new ConversionProcessError(
      `Command '${cmdName}' failed: ${getErrorMessage(error)}`,
      error,
    );
  }
}

async function encryptFileStream(
  inputPath: string,
  outputPath: string,
  keyHex: string,
): Promise<void> {
  try {
    const key = Buffer.from(keyHex);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    const readStream = fs.createReadStream(inputPath);
    const writeStream = fs.createWriteStream(outputPath);

    // FIX: Arrow function để khớp type
    if (!writeStream.write(iv)) {
      await new Promise<void>((resolve) =>
        writeStream.once('drain', () => resolve()),
      );
    }

    await pipeline(readStream, cipher, writeStream, { end: false });

    const authTag = cipher.getAuthTag();

    await new Promise<void>((resolve, reject) => {
      writeStream.write(authTag, (err) => {
        if (err) return reject(err);
        writeStream.end(() => resolve());
      });
    });
  } catch (error: unknown) {
    throw new EncryptionError(
      `Encryption failed for ${inputPath}: ${getErrorMessage(error)}`,
      error,
    );
  }
}

// ==========================================
// 5. MAIN LOGIC
// ==========================================

async function convertAndEncrypt(task: ConversionTask): Promise<WorkerResult> {
  const { objFilePath, outputDir, baseName, encryptionKey, config } = task;
  const tempDir = path.dirname(objFilePath);

  const paths = {
    initialGlb: path.join(tempDir, `${baseName}.initial.glb`),
    simplifiedGlb: path.join(tempDir, `${baseName}.simplified.glb`),
    optimizedGlb: path.join(tempDir, `${baseName}.optimized.glb`),
    finalEncrypted: path.join(outputDir, `${baseName}.optimized.glb.enc`),
  };

  const tempFiles = [paths.initialGlb, paths.simplifiedGlb, paths.optimizedGlb];

  try {
    if (!fs.existsSync(objFilePath)) {
      throw new FileSystemError(`Input file not found: ${objFilePath}`);
    }

    const bins = resolveBinaries();

    await runCommand(
      bins.obj2gltf,
      ['-i', objFilePath, '-o', paths.initialGlb, '--binary'],
      config.timeout,
    );

    await runCommand(
      bins.gltfTransform,
      [
        'simplify',
        paths.initialGlb,
        paths.simplifiedGlb,
        '--ratio',
        config.ratio.toString(),
        '--error',
        config.threshold.toString(),
      ],
      config.timeout,
    );

    await runCommand(
      bins.gltfPipeline,
      [
        '-i',
        paths.simplifiedGlb,
        '-o',
        paths.optimizedGlb,
        '--draco.compressionLevel=10',
      ],
      config.timeout,
    );

    await fs.ensureDir(outputDir);
    await encryptFileStream(
      paths.optimizedGlb,
      paths.finalEncrypted,
      encryptionKey,
    );

    return { success: true, path: paths.finalEncrypted };
  } catch (error: unknown) {
    if (error instanceof WorkerBaseError) {
      throw error;
    }
    throw new Error(`Unexpected Worker Error: ${getErrorMessage(error)}`);
  } finally {
    await Promise.all(
      tempFiles.map((f) =>
        fs.remove(f).catch(() => {
          /* ignore */
        }),
      ),
    );
  }
}

export default convertAndEncrypt;
```

## File: src/modules/dental/infrastructure/workers/piscina.provider.ts
```
import { Provider, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as path from 'path';
import * as fs from 'fs';

// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires, @typescript-eslint/no-unsafe-assignment
const Piscina = require('piscina');

export const PISCINA_POOL = 'PISCINA_POOL';

export const PiscinaProvider: Provider = {
  provide: PISCINA_POOL,
  useFactory: (config: ConfigService) => {
    const logger = new Logger('PiscinaProvider');
    const isProduction = process.env.NODE_ENV === 'production';

    const projectRoot = process.cwd();
    const workerRelativePath =
      'src/modules/dental/infrastructure/workers/conversion.worker';

    let workerPath: string;

    if (isProduction) {
      const prodPath1 = path.join(
        projectRoot,
        'dist',
        workerRelativePath + '.js',
      );
      const prodPath2 = path.join(
        projectRoot,
        'dist',
        workerRelativePath.replace('src/', '') + '.js',
      );

      if (fs.existsSync(prodPath1)) {
        workerPath = prodPath1;
      } else if (fs.existsSync(prodPath2)) {
        workerPath = prodPath2;
      } else {
        workerPath = path.join(__dirname, 'conversion.worker.js');
      }
    } else {
      workerPath = path.join(projectRoot, workerRelativePath + '.ts');
    }

    if (!fs.existsSync(workerPath)) {
      logger.error(
        `CRITICAL: Worker file not found at calculated path: ${workerPath}`,
      );
      const dirContent = fs.readdirSync(__dirname).join(', ');
      logger.error(`Dirname content: [${dirContent}]`);
      throw new Error(`Worker file not found: ${workerPath}`);
    }

    logger.log(`🏊 Initializing Piscina with worker: ${workerPath}`);

    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return
    return new Piscina({
      filename: workerPath,
      minThreads: config.get<number>('dental.minThreads') || 0,
      maxThreads: config.get<number>('dental.maxThreads') || 4,
      execArgv: workerPath.endsWith('.ts') ? ['-r', 'ts-node/register'] : [],
    });
  },
  inject: [ConfigService],
};
```

## File: src/modules/dental/infrastructure/adapters/fs-dental-storage.adapter.ts
```
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs-extra';
import * as path from 'path';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const AdmZip = require('adm-zip');
import { IDentalStorage } from '../../domain/ports/dental-storage.port';

@Injectable()
export class FileSystemDentalStorage implements IDentalStorage {
  private readonly uploadDir: string;
  private readonly outputDir: string;

  constructor(private readonly config: ConfigService) {
    const rawUploadDir = this.config.get('dental.uploadDir');
    const rawOutputDir = this.config.get('dental.outputDir');
    if (!rawUploadDir || !rawOutputDir)
      throw new Error('Dental Config Missing');

    this.uploadDir = path.resolve(rawUploadDir);
    this.outputDir = path.resolve(rawOutputDir);
  }

  ensureDirectories(): void {
    fs.ensureDirSync(this.uploadDir);
    fs.ensureDirSync(this.outputDir);
  }

  getUploadDir(): string {
    return this.uploadDir;
  }
  getOutputDir(): string {
    return this.outputDir;
  }

  async saveTempFile(file: Express.Multer.File): Promise<string> {
    // Multer đã lưu file rồi, hàm này chỉ để confirm hoặc move nếu cần
    return file.path;
  }

  async extractZip(zipPath: string, extractPath: string): Promise<void> {
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractPath, true);
  }

  async removeFile(path: string): Promise<void> {
    await fs.remove(path).catch(() => {});
  }

  async removeDirectory(path: string): Promise<void> {
    await fs.remove(path).catch(() => {});
  }

  async findObjFilesRecursively(dir: string): Promise<string[]> {
    return this.findFiles(dir, '.obj');
  }

  async findEncFilesRecursively(dir: string): Promise<string[]> {
    return this.findFiles(dir, '.enc');
  }

  private async findFiles(dir: string, ext: string): Promise<string[]> {
    let results: string[] = [];
    try {
      const list = await fs.readdir(dir);
      for (const file of list) {
        const fullPath = path.resolve(dir, file);
        const stat = await fs.stat(fullPath);
        if (stat && stat.isDirectory()) {
          results = results.concat(await this.findFiles(fullPath, ext));
        } else if (file.toLowerCase().endsWith(ext)) {
          results.push(fullPath);
        }
      }
    } catch (e) {
      /* ignore */
    }
    return results;
  }
}
```

## File: src/modules/dental/infrastructure/adapters/piscina-worker.adapter.ts
```
import { Injectable, Inject } from '@nestjs/common';
import Piscina from 'piscina';
import {
  IDentalWorker,
  ConversionJob,
  WorkerResult,
} from '../../domain/ports/dental-worker.port';
import { PISCINA_POOL } from '../workers/piscina.provider';

@Injectable()
export class PiscinaDentalWorker implements IDentalWorker {
  constructor(@Inject(PISCINA_POOL) private readonly pool: Piscina) {}

  async runTask(task: ConversionJob): Promise<WorkerResult> {
    return this.pool.run(task);
  }
}
```

## File: src/modules/dental/infrastructure/persistence/drizzle-ortho.repository.ts
```
import { Injectable } from '@nestjs/common';
import { eq, desc, and, asc } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  IOrthoRepository,
  CreateCaseParams,
  OrthoCase,
  FullCaseInput,
  CaseDetailsDTO
} from '../../domain/repositories/ortho.repository';
import {
  patients,
  cases,
  treatmentSteps,
  clinics,
  dentists,
} from '@database/schema/ortho.schema';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleOrthoRepository
  extends DrizzleBaseRepository
  implements IOrthoRepository
{
  async createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string> {
     const runInTx = async (dbTx: any) => {
        const clinicCode = data.clinicName.toUpperCase().replace(/\s+/g, '_').substring(0, 10);

        let clinicId: number;
        const existingClinic = await dbTx.select().from(clinics).where(eq(clinics.clinicCode, clinicCode)).limit(1);
        if (existingClinic.length > 0) {
            clinicId = existingClinic[0].id;
        } else {
            const [newClinic] = await dbTx.insert(clinics).values({
                name: data.clinicName,
                clinicCode: clinicCode,
            }).returning();
            clinicId = newClinic.id;
        }

        let dentistId: number | null = null;
        if (data.doctorName) {
            const existingDentist = await dbTx.select().from(dentists)
                .where(and(eq(dentists.fullName, data.doctorName), eq(dentists.clinicId, clinicId)))
                .limit(1);
            if (existingDentist.length > 0) {
                dentistId = existingDentist[0].id;
            } else {
                const [newDentist] = await dbTx.insert(dentists).values({
                    fullName: data.doctorName,
                    clinicId: clinicId,
                }).returning();
                dentistId = newDentist.id;
            }
        }

        let patientId: number;
        const existingPatient = await dbTx.select().from(patients).where(eq(patients.patientCode, data.patientCode)).limit(1);
        if (existingPatient.length > 0) {
            patientId = existingPatient[0].id;
        } else {
            const [newPatient] = await dbTx.insert(patients).values({
                fullName: data.patientName,
                patientCode: data.patientCode,
                clinicId: clinicId,
                gender: data.gender,
                birthDate: data.dob ? data.dob.toISOString().split('T')[0] : null,
            }).returning();
            patientId = newPatient.id;
        }

        const [newCase] = await dbTx.insert(cases).values({
            patientId: patientId,
            dentistId: dentistId,
            productType: data.productType,
            status: 'PROCESSING',
            notes: data.notes,
            startedAt: new Date(),
        }).returning();

        return String(newCase.id);
     };

     if (tx) return runInTx(tx);
     return this.db.transaction(runInTx);
  }

  // ✅ NEW: Hàm Update Movement Data
  async updateStepMovementData(caseId: string, stepIndex: number, teethData: any, tx?: Transaction): Promise<void> {
      const db = this.getDb(tx);
      const cId = Number(caseId);

      // Kiểm tra xem step đã tồn tại chưa
      const existingStep = await db.select().from(treatmentSteps)
          .where(and(eq(treatmentSteps.caseId, cId), eq(treatmentSteps.stepIndex, stepIndex)))
          .limit(1);

      if (existingStep.length > 0) {
          // Update
          await db.update(treatmentSteps)
              .set({ teethData: teethData })
              .where(eq(treatmentSteps.id, existingStep[0].id));
      } else {
          // Insert mới (nếu chưa có model nhưng có data trước)
          await db.insert(treatmentSteps).values({
              caseId: cId,
              stepIndex: stepIndex,
              teethData: teethData
          });
      }
  }

  async getCaseDetails(identifier: string, isCaseId: boolean, tx?: Transaction): Promise<CaseDetailsDTO | null> {
      const db = this.getDb(tx);
      let selection = {
          patientName: patients.fullName,
          patientCode: patients.patientCode,
          caseId: cases.id,
          doctorName: dentists.fullName,
          clinicName: clinics.name,
          createdAt: cases.createdAt
      };

      let query;
      if (isCaseId) {
          query = db.select(selection).from(cases)
              .innerJoin(patients, eq(cases.patientId, patients.id))
              .leftJoin(dentists, eq(cases.dentistId, dentists.id))
              .leftJoin(clinics, eq(patients.clinicId, clinics.id))
              .where(eq(cases.id, Number(identifier)))
              .limit(1);
      } else {
          query = db.select(selection).from(cases)
              .innerJoin(patients, eq(cases.patientId, patients.id))
              .leftJoin(dentists, eq(cases.dentistId, dentists.id))
              .leftJoin(clinics, eq(patients.clinicId, clinics.id))
              .where(eq(patients.patientCode, identifier))
              .orderBy(desc(cases.createdAt))
              .limit(1);
      }
      const result = await query;
      return result[0] || null;
  }

  async checkCaseBelongsToPatient(caseId: string, patientCode: string, tx?: Transaction): Promise<boolean> {
      const db = this.getDb(tx);
      if (isNaN(Number(caseId))) return false;
      const result = await db.select({ id: cases.id })
        .from(cases)
        .innerJoin(patients, eq(cases.patientId, patients.id))
        .where(and(eq(cases.id, Number(caseId)), eq(patients.patientCode, patientCode)))
        .limit(1);
      return result.length > 0;
  }

  async findLatestCaseIdByCode(code: string, tx?: Transaction): Promise<string | null> {
    const db = this.getDb(tx);
    if (!isNaN(Number(code))) {
        const caseById = await db.query.cases.findFirst({ where: eq(cases.id, Number(code)) });
        if (caseById) return String(caseById.id);
    }
    const result = await db.select({ caseId: cases.id })
    .from(cases)
    .innerJoin(patients, eq(cases.patientId, patients.id))
    .where(eq(patients.patientCode, code))
    .orderBy(desc(cases.createdAt))
    .limit(1);

    if (result.length > 0) return String(result[0].caseId);
    return null;
  }

  async findCasesByPatientCode(patientCode: string, tx?: Transaction): Promise<any[]> {
    const db = this.getDb(tx);
    return await db.select({
        caseId: cases.id,
        status: cases.status,
        createdAt: cases.createdAt,
        notes: cases.notes,
        productType: cases.productType,
        doctorName: dentists.fullName
    })
    .from(cases)
    .innerJoin(patients, eq(cases.patientId, patients.id))
    .leftJoin(dentists, eq(cases.dentistId, dentists.id))
    .where(eq(patients.patientCode, patientCode))
    .orderBy(desc(cases.createdAt));
  }

  async getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]> {
    const db = this.getDb(tx);
    // ✅ QUAN TRỌNG: Select luôn teethData
    return await db.select()
        .from(treatmentSteps)
        .where(eq(treatmentSteps.caseId, caseId))
        .orderBy(asc(treatmentSteps.stepIndex));
  }

  // Legacy
  async findPatientByCode(code: string, tx?: Transaction): Promise<any | null> { return null; }
  async createPatient(data: any, tx?: Transaction): Promise<any> { return null; }
  async createCase(data: CreateCaseParams, tx?: Transaction): Promise<OrthoCase> { throw new Error(""); }
  async findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null> { return null; }
  async saveSteps(caseId: number, steps: any[], tx?: Transaction): Promise<void> {}
}
```

## File: src/modules/dental/infrastructure/dtos/upload-case.dto.ts
```
import {
  IsString,
  IsOptional,
  IsEnum,
  IsDateString,
  IsNotEmpty,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum Gender {
  Male = 'Male',
  Female = 'Female',
  Other = 'Other',
}

export enum ProductType {
  Aligner = 'aligner',
  Retainer = 'retainer',
}

export class UploadCaseDto {
  @ApiProperty({
    description: 'Full Name of the Patient',
    example: 'Nguyen Van A',
  })
  @IsString()
  @IsNotEmpty()
  patientName: string;

  @ApiProperty({ description: 'Unique Patient Code', example: 'PAT-12345' })
  @IsString()
  @IsNotEmpty()
  patientCode: string;

  @ApiProperty({ description: 'Gender', enum: Gender, required: false })
  @IsOptional()
  @IsEnum(Gender)
  gender?: Gender;

  @ApiProperty({
    description: 'Date of Birth (ISO)',
    required: false,
    example: '1990-01-01',
  })
  @IsOptional()
  @IsDateString()
  dob?: string;

  @ApiProperty({ description: 'Clinic Name', example: 'Smile Dental' })
  @IsString()
  @IsNotEmpty()
  clinicName: string;

  @ApiProperty({
    description: 'Doctor Name',
    required: false,
    example: 'Dr. House',
  })
  @IsOptional()
  @IsString()
  doctorName?: string;

  @ApiProperty({
    description: 'Product Type',
    enum: ProductType,
    default: ProductType.Aligner,
  })
  @IsOptional()
  @IsEnum(ProductType)
  productType: ProductType = ProductType.Aligner;

  @ApiProperty({ description: 'Additional Notes', required: false })
  @IsOptional()
  @IsString()
  notes?: string;

  @ApiProperty({ type: 'string', format: 'binary' })
  file: any;
}
```

## File: src/modules/dental/domain/ports/dental-worker.port.ts
```
export const IDentalWorker = Symbol('IDentalWorker');

export interface ConversionJob {
  objFilePath: string;
  outputDir: string;
  baseName: string;
  encryptionKey: string;
  config: {
    ratio: number;
    threshold: number;
    timeout: number;
  };
}

export interface WorkerResult {
  success: boolean;
  path: string;
}

export interface IDentalWorker {
  runTask(task: ConversionJob): Promise<WorkerResult>;
}
```

## File: src/modules/dental/domain/ports/dental-storage.port.ts
```
export const IDentalStorage = Symbol('IDentalStorage');

export interface DentalFile {
  path: string;
  filename: string;
}

export interface IDentalStorage {
  ensureDirectories(): void;
  saveTempFile(file: Express.Multer.File): Promise<string>;
  extractZip(zipPath: string, extractPath: string): Promise<void>;
  findObjFilesRecursively(dir: string): Promise<string[]>;
  findEncFilesRecursively(dir: string): Promise<string[]>;
  removeFile(path: string): Promise<void>;
  removeDirectory(path: string): Promise<void>;
  getUploadDir(): string;
  getOutputDir(): string;
}
```

## File: src/modules/dental/domain/repositories/ortho.repository.ts
```
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export interface OrthoCase { id: number; orderId?: string | null; patientId: number; status: string | null; createdAt: Date | null; }
export interface CreateCaseParams { patientId: number; dentistId?: number; productType: 'aligner' | 'retainer'; scanDate?: Date; }
export interface FullCaseInput { patientName: string; patientCode: string; gender?: 'Male' | 'Female' | 'Other'; dob?: Date; clinicName: string; doctorName?: string; productType: 'aligner' | 'retainer'; notes?: string; }
export interface CaseDetailsDTO { patientName: string; patientCode: string; caseId: number; doctorName?: string; clinicName?: string; createdAt: Date; }

export const IOrthoRepository = Symbol('IOrthoRepository');

export interface IOrthoRepository {
  createFullCase(data: FullCaseInput, tx?: Transaction): Promise<string>;
  findLatestCaseIdByCode(code: string, tx?: Transaction): Promise<string | null>;
  checkCaseBelongsToPatient(caseId: string, patientCode: string, tx?: Transaction): Promise<boolean>;
  findCasesByPatientCode(patientCode: string, tx?: Transaction): Promise<any[]>;
  getCaseDetails(identifier: string, isCaseId: boolean, tx?: Transaction): Promise<CaseDetailsDTO | null>;
  getStepsByCaseId(caseId: number, tx?: Transaction): Promise<any[]>;

  // ✅ NEW
  updateStepMovementData(caseId: string, stepIndex: number, teethData: any, tx?: Transaction): Promise<void>;

  // Legacy
  findPatientByCode(code: string, tx?: Transaction): Promise<any | null>;
  createPatient(data: any, tx?: Transaction): Promise<any>;
  createCase(data: any, tx?: Transaction): Promise<any>;
  findCaseById(id: number, tx?: Transaction): Promise<OrthoCase | null>;
  saveSteps(caseId: number, steps: any[], tx?: Transaction): Promise<void>;
}
```

## File: src/modules/dental/dental.module.ts
```
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DentalController } from './infrastructure/controllers/dental.controller';
import { DentalService } from './application/services/dental.service';
import { PiscinaProvider } from './infrastructure/workers/piscina.provider';
import { FileSystemDentalStorage } from './infrastructure/adapters/fs-dental-storage.adapter';
import { PiscinaDentalWorker } from './infrastructure/adapters/piscina-worker.adapter';
import { DrizzleOrthoRepository } from './infrastructure/persistence/drizzle-ortho.repository';
import { IDentalStorage } from './domain/ports/dental-storage.port';
import { IDentalWorker } from './domain/ports/dental-worker.port';
import { IOrthoRepository } from './domain/repositories/ortho.repository';
import dentalConfig from '@config/dental.config';

@Module({
  imports: [ConfigModule.forFeature(dentalConfig)],
  controllers: [DentalController],
  providers: [
    DentalService,
    PiscinaProvider,
    {
      provide: IDentalStorage,
      useClass: FileSystemDentalStorage,
    },
    {
      provide: IDentalWorker,
      useClass: PiscinaDentalWorker,
    },
    // ✅ Đăng ký Repository mới
    {
      provide: IOrthoRepository,
      useClass: DrizzleOrthoRepository,
    },
  ],
})
export class DentalModule {}
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
import { Response } from 'express'; // Nhớ import Response từ express
import { BYPASS_TRANSFORM_KEY } from '../decorators/bypass-transform.decorator';

// 1. Định nghĩa Interface cho object trả về để kiểm soát kiểu dữ liệu
export interface AppResponse<T> {
  success: boolean;
  statusCode: number;
  message: string;
  result: T;
}

@Injectable()
export class TransformResponseInterceptor<T> implements NestInterceptor<
  T,
  AppResponse<T> | StreamableFile
> {
  constructor(private reflector: Reflector) {}

  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<AppResponse<T> | StreamableFile> {
    const bypass = this.reflector.get<boolean>(
      BYPASS_TRANSFORM_KEY,
      context.getHandler(),
    );

    if (bypass) {
      return next.handle() as Observable<AppResponse<T> | StreamableFile>;
    }

    return next.handle().pipe(
      // FIX LỖI Ở ĐÂY:
      // Thay vì map((data) => ...), ta khai báo map((data: T) => ...)
      // TypeScript sẽ hiểu data có kiểu T, không phải any.
      map((data: T) => {
        // Double check: Nếu data là StreamableFile thì return luôn
        if (data instanceof StreamableFile) {
          return data;
        }

        // Lấy Response object từ Express để lấy statusCode chính xác
        const response = context.switchToHttp().getResponse<Response>();
        const status = response.statusCode;

        return {
          success: true,
          statusCode: status,
          message:
            this.reflector.get<string>(
              'response_message',
              context.getHandler(),
            ) || 'Success',
          result: data, // Lúc này việc gán data (T) vào result là an toàn
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

// 1. Định nghĩa Interface cho cấu trúc lỗi mặc định của NestJS
interface NestErrorResponse {
  statusCode: number;
  message: string | string[];
  error: string;
}

// 2. Định nghĩa Interface cho cấu trúc response trả về client
interface ApiResponse {
  success: boolean;
  statusCode: number;
  message: string;
  errors: string | string[] | null;
  path: string;
  timestamp: string;
}

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status = exception.getStatus
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    // 3. Lấy response gốc (có thể là string hoặc object)
    const exceptionResponse = exception.getResponse();

    // 4. Khởi tạo giá trị mặc định
    let message = 'Error';
    let errors: string | string[] | null = null;

    // 5. Xử lý Logic Type-Safe
    if (typeof exceptionResponse === 'string') {
      // Trường hợp 1: throw new BadRequestException('Lỗi gì đó')
      message = exceptionResponse;
    } else if (
      typeof exceptionResponse === 'object' &&
      exceptionResponse !== null
    ) {
      // Trường hợp 2: Lỗi từ class-validator hoặc NestJS chuẩn
      // Ép kiểu an toàn về Interface đã định nghĩa
      const responseObj = exceptionResponse as NestErrorResponse;

      // Logic cũ của bạn: Ưu tiên lấy 'error' làm message chính (VD: "Bad Request")
      // Nếu không có 'error', lấy 'message' (nếu nó là string)
      if (responseObj.error) {
        message = responseObj.error;
      } else if (typeof responseObj.message === 'string') {
        message = responseObj.message;
      }

      // 'errors' chứa chi tiết (VD: mảng các field validate sai)
      errors = responseObj.message || null;
    }

    // 6. Tạo response body theo Interface chuẩn
    const responseBody: ApiResponse = {
      success: false,
      statusCode: status,
      message: message,
      errors: errors,
      path: request.url,
      timestamp: new Date().toISOString(),
    };

    response.status(status).json(responseBody);
  }
}
```

## File: src/core/decorators/bypass-transform.decorator.ts
```
import { SetMetadata } from '@nestjs/common';

export const BYPASS_TRANSFORM_KEY = 'bypass_transform';
export const BypassTransform = () => SetMetadata(BYPASS_TRANSFORM_KEY, true);
```

## File: src/core/shared/application/ports/file-parser.port.ts
```
export const IFileParser = Symbol('IFileParser');

export interface IFileParser {
  parseCsv<T>(content: string): T[];
}
```

## File: src/core/shared/application/ports/transaction-manager.port.ts
```
export type Transaction = unknown; // Opaque type

// 1. Token (Runtime Identifier)
export const ITransactionManager = Symbol('ITransactionManager');

// 2. Interface (Type)
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
import { Type } from '@nestjs/common';

export const IEventBus = Symbol('IEventBus');

export interface IEventBus {
  publish<T extends IDomainEvent>(event: T): Promise<void>;

  // Hàm này dùng cho cơ chế Auto-Discovery đăng ký handler
  subscribe<T extends IDomainEvent>(
    eventCls: Type<T> | string,
    handler: (event: T) => Promise<void>,
  ): void;
}
```

## File: src/core/shared/application/ports/logger.port.ts
```
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
}

export interface LogContext {
  requestId?: string;
  userId?: number | string;
  ipAddress?: string;
  method?: string;
  url?: string;
  [key: string]: any;
}

// ✅ PRO WAY: Định nghĩa Token ở đây
export const LOGGER_TOKEN = 'ILogger';

export interface ILogger {
  debug(message: string, context?: LogContext): void;
  info(message: string, context?: LogContext): void;
  warn(message: string, context?: LogContext): void;
  error(message: string, error?: Error, context?: LogContext): void;

  withContext(context: LogContext): ILogger;
  createChildLogger(module: string): ILogger;
}
```

## File: src/core/shared/application/ports/cache.port.ts
```
// Token để Inject
export const ICacheService = Symbol('ICacheService');

// Interface trừu tượng
export interface ICacheService {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown, ttl?: number): Promise<void>;
  del(key: string): Promise<void>;
  reset(): Promise<void>;
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
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { DRIZZLE } from '@database/drizzle.provider';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';

@Injectable()
export class DrizzleBaseRepository {
  constructor(
    @Inject(DRIZZLE) protected readonly db: NodePgDatabase<typeof schema>,
    // @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  protected getDb(tx?: Transaction): NodePgDatabase<typeof schema> {
    return tx ? (tx as NodePgDatabase<typeof schema>) : this.db;
  }
}
```

## File: src/core/shared/infrastructure/persistence/drizzle-transaction.manager.ts
```
import { Inject, Injectable } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { DRIZZLE } from '@database/drizzle.provider';
import {
  ITransactionManager,
  Transaction,
} from '@core/shared/application/ports/transaction-manager.port';

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

## File: src/core/shared/infrastructure/context/request-context.service.ts
```
import { Injectable } from '@nestjs/common';
import { AsyncLocalStorage } from 'async_hooks';

export class RequestContext {
  constructor(
    public readonly requestId: string,
    public readonly url: string,
  ) {}
}

@Injectable()
export class RequestContextService {
  // Static để có thể gọi ở bất cứ đâu (kể cả nơi không inject được)
  private static readonly als = new AsyncLocalStorage<RequestContext>();

  static run(context: RequestContext, callback: () => void) {
    this.als.run(context, callback);
  }

  static getRequestId(): string {
    const store = this.als.getStore();
    return store?.requestId || 'sys-' + process.pid; // Fallback nếu không có request (VD: Cronjob)
  }

  static getContext(): RequestContext | undefined {
    return this.als.getStore();
  }
}
```

## File: src/core/shared/infrastructure/cache/redis-cache.adapter.ts
```
import { Injectable, Inject, OnModuleInit } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { ICacheService } from '../../application/ports/cache.port';
import { ILogger, LOGGER_TOKEN } from '../../application/ports/logger.port';

@Injectable()
export class RedisCacheAdapter implements ICacheService, OnModuleInit {
  constructor(
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  onModuleInit() {
    const store: any = (this.cacheManager as any).store;

    // --- DEBUG BLOCK ---
    const storeName = store?.name || store?.constructor?.name || 'Unknown';
    this.logger.info(`🔍 DEBUG: Cache Store Name = [${storeName}]`);

    // Kiểm tra xem có phải Redis không
    const isRedis = storeName === 'RedisStore' || (store && store.client);

    if (isRedis) {
      this.logger.info('🚀 CACHE STATUS: REDIS IS ACTIVE (Confirmed)');
    } else {
      this.logger.warn(
        '⚠️ CACHE STATUS: NOT REDIS! INSPECTING STORE OBJECT...',
      );
      console.log('Store Keys:', Object.keys(store || {}));
    }
    // -------------------
  }

  async get<T>(key: string): Promise<T | undefined> {
    try {
      const start = Date.now();
      const value = await this.cacheManager.get<T>(key);

      // Chỉ log debug
      this.logger.debug(`Redis GET`, {
        key,
        hit: !!value,
        duration: `${Date.now() - start}ms`,
      });

      return value;
    } catch (error) {
      this.logger.error(`Redis GET Error`, error as Error);
      return undefined;
    }
  }

  async set(key: string, value: unknown, ttl?: number): Promise<void> {
    try {
      const finalTtl = ttl ? ttl * 1000 : undefined;
      await this.cacheManager.set(key, value, finalTtl as any);
      this.logger.debug(`Redis SET`, { key });
    } catch (error) {
      this.logger.error(`Redis SET Error`, error as Error);
    }
  }

  async del(key: string): Promise<void> {
    try {
      await this.cacheManager.del(key);
      this.logger.debug(`Redis DEL`, { key });
    } catch (error) {
      this.logger.error(`Redis DEL Error`, error as Error);
    }
  }

  async reset(): Promise<void> {
    try {
      const client = this.cacheManager as any;
      if (client.store && typeof client.store.clear === 'function') {
        await client.store.clear();
      } else if (typeof client.reset === 'function') {
        await client.reset();
      }
      this.logger.warn(`Redis RESET ALL`);
    } catch (error) {
      this.logger.error(`Redis RESET Error`, error as Error);
    }
  }
}
```

## File: src/core/shared/infrastructure/cache/redis-cache.module.ts
```
import { Module, Global } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ICacheService } from '../../application/ports/cache.port';
import { RedisCacheAdapter } from './redis-cache.adapter';
import redisConfig from '@config/redis.config';
import { redisStore } from 'cache-manager-redis-yet';

@Global()
@Module({
  imports: [ConfigModule.forFeature(redisConfig)],
  providers: [
    {
      provide: CACHE_MANAGER,
      useFactory: async (configService: ConfigService) => {
        const host = configService.get('redis.host');
        const port = configService.get('redis.port');
        const ttl = (configService.get('redis.ttl') || 300) * 1000;

        console.log(`🔌 Connecting to Redis at ${host}:${port}...`);

        // Sử dụng redis-yet (chuẩn mới)
        const store = await redisStore({
          socket: { host, port },
          ttl,
        });

        console.log('✅ Redis Store Created!');

        // Fix lỗi import cache-manager (CommonJS vs ESM)
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const cm = require('cache-manager');
        const createCache =
          cm.createCache ||
          (cm.default && cm.default.createCache) ||
          cm.caching;

        if (!createCache) throw new Error('Cannot find createCache function');

        const cache = createCache(store);
        // Gán ngược store để Adapter check được
        if (!cache.store) cache.store = store;

        return cache;
      },
      inject: [ConfigService],
    },
    {
      provide: ICacheService,
      useClass: RedisCacheAdapter,
    },
  ],
  exports: [ICacheService, CACHE_MANAGER],
})
export class RedisCacheModule {}
```

## File: src/core/shared/infrastructure/event-bus/adapters/in-memory-event-bus.adapter.ts
```
import { Injectable, Logger } from '@nestjs/common';
import { Type } from '@nestjs/common';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

@Injectable()
export class InMemoryEventBusAdapter implements IEventBus {
  private readonly logger = new Logger(InMemoryEventBusAdapter.name);
  private handlers = new Map<
    string,
    Array<(event: IDomainEvent) => Promise<void>>
  >();

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    const eventName = event.eventName;
    const handlers = this.handlers.get(eventName) || [];

    Promise.all(handlers.map((handler) => handler(event))).catch((err) =>
      this.logger.error(`Error handling event ${eventName}`, err),
    );
  }

  subscribe<T extends IDomainEvent>(
    eventCls: Type<T> | string,
    handler: (event: T) => Promise<void>,
  ): void {
    let eventName: string;

    if (typeof eventCls === 'string') {
      eventName = eventCls;
    } else {
      // ✅ SAFE FIX: Sử dụng Object.create để tránh gọi constructor thực thi logic validate
      // Điều này ngăn chặn crash app khi khởi tạo Event Class rỗng
      const instance = Object.create(eventCls.prototype);
      // Nếu eventName là property instance (được gán trong constructor), ta không lấy được ở đây
      // NHƯNG, với kiến trúc hiện tại, eventName thường hardcode.
      // Cách tốt nhất: Fallback về tên Class nếu instance.eventName undefined
      eventName = instance.eventName || eventCls.name;

      // Nếu trường hợp eventName bắt buộc phải lấy từ instance thật và khác tên class
      // thì nên refactor Event thành có static property.
      // Ở đây ta dùng instance giả lập an toàn.
      if (!eventName) {
        try {
          const realInstance = new eventCls({} as any, {} as any);
          eventName = realInstance.eventName;
        } catch (e) {
          eventName = eventCls.name;
          this.logger.warn(
            `Could not extract eventName from ${eventCls.name}, using class name.`,
          );
        }
      }
    }

    if (!this.handlers.has(eventName)) {
      this.handlers.set(eventName, []);
    }
    this.handlers.get(eventName)!.push(handler as any);
    this.logger.log(`Subscribed to event: ${eventName}`);
  }
}
```

## File: src/core/shared/infrastructure/event-bus/adapters/rabbitmq-event-bus.adapter.ts
```
import {
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from '@nestjs/common';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

@Injectable()
export class RabbitMQEventBusAdapter
  implements IEventBus, OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(RabbitMQEventBusAdapter.name);

  async onModuleInit() {
    this.logger.log('Connecting to RabbitMQ...');
  }

  async onModuleDestroy() {
    this.logger.log('Closing RabbitMQ connection...');
  }

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    this.logger.log(`[RabbitMQ] Publishing: ${event.eventName}`);
  }

  subscribe<T extends IDomainEvent>(
    eventCls: any,
    handler: (event: T) => Promise<void>,
  ): void {
    this.logger.log(`[RabbitMQ] Subscribing to: ${eventCls}`);
  }
}
```

## File: src/core/shared/infrastructure/event-bus/adapters/kafka-event-bus.adapter.ts
```
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

@Injectable()
export class KafkaEventBusAdapter implements IEventBus, OnModuleInit {
  private readonly logger = new Logger(KafkaEventBusAdapter.name);

  async onModuleInit() {
    this.logger.log('Connecting to Kafka...');
  }

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    this.logger.log(`[Kafka] Publishing: ${event.eventName}`);
  }

  subscribe<T extends IDomainEvent>(
    eventCls: any,
    handler: (event: T) => Promise<void>,
  ): void {
    this.logger.log(`[Kafka] Subscribing to: ${eventCls}`);
  }
}
```

## File: src/core/shared/infrastructure/event-bus/decorators/event-handler.decorator.ts
```
import { SetMetadata } from '@nestjs/common';
import { Type } from '@nestjs/common';
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

export const EVENT_HANDLER_METADATA = 'EVENT_HANDLER_METADATA';

export const EventHandler = (event: Type<IDomainEvent> | string) =>
  SetMetadata(EVENT_HANDLER_METADATA, event);
```

## File: src/core/shared/infrastructure/event-bus/event.explorer.ts
```
import { Injectable, OnModuleInit, Inject } from '@nestjs/common';
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { EVENT_HANDLER_METADATA } from './decorators/event-handler.decorator';

@Injectable()
export class EventExplorer implements OnModuleInit {
  constructor(
    private readonly discoveryService: DiscoveryService,
    private readonly metadataScanner: MetadataScanner,
    private readonly reflector: Reflector,
    @Inject(IEventBus) private readonly eventBus: IEventBus,
  ) {}

  onModuleInit() {
    this.explore();
  }

  private explore() {
    const providers = this.discoveryService.getProviders();

    providers
      .filter((wrapper) => wrapper.instance && !wrapper.isAlias)
      .forEach((wrapper) => {
        const { instance } = wrapper;
        const prototype = Object.getPrototypeOf(instance);
        if (!prototype) return;

        this.metadataScanner.scanFromPrototype(
          instance,
          prototype,
          (methodName) => {
            const method = instance[methodName];
            const eventCls = this.reflector.get(EVENT_HANDLER_METADATA, method);

            if (eventCls) {
              this.eventBus.subscribe(eventCls, method.bind(instance));
            }
          },
        );
      });
  }
}
```

## File: src/core/shared/infrastructure/event-bus/event-bus.module.ts
```
import { Module, Global } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { DiscoveryModule } from '@nestjs/core';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { InMemoryEventBusAdapter } from './adapters/in-memory-event-bus.adapter';
import { RabbitMQEventBusAdapter } from './adapters/rabbitmq-event-bus.adapter';
import { KafkaEventBusAdapter } from './adapters/kafka-event-bus.adapter';
import { EventExplorer } from './event.explorer';
import eventBusConfig from '@config/event-bus.config';

@Global()
@Module({
  imports: [ConfigModule.forFeature(eventBusConfig), DiscoveryModule],
  providers: [
    EventExplorer,
    {
      provide: IEventBus,
      useFactory: (config: ConfigService) => {
        const type = config.get('eventBus.type');
        console.log(`🔌 EventBus initialized with type: ${type}`);

        switch (type) {
          case 'rabbitmq':
            return new RabbitMQEventBusAdapter();
          case 'kafka':
            return new KafkaEventBusAdapter();
          case 'memory':
          default:
            return new InMemoryEventBusAdapter();
        }
      },
      inject: [ConfigService],
    },
  ],
  exports: [IEventBus],
})
export class EventBusModule {}
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

## File: src/core/shared/utils/password.util.ts
```
import * as bcrypt from 'bcrypt';
export class PasswordUtil {
  static async hash(p: string) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(p, salt);
  }
  static async compare(p: string, h: string) {
    return bcrypt.compare(p, h);
  }
  static validateStrength(p: string) {
    return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(p);
  }
}
```

## File: src/core/shared/types/common.types.ts
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

## File: src/core/core.module.ts
```
import { Module } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';

import { TransformResponseInterceptor } from './interceptors/transform-response.interceptor';
import { HttpExceptionFilter } from './filters/http-exception.filter';
import { RequestContextService } from './shared/infrastructure/context/request-context.service';

@Module({
  providers: [
    RequestContextService, // Đăng ký Service này
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
  exports: [RequestContextService],
})
export class CoreModule {}
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

## File: src/config/redis.config.ts
```
import { registerAs } from '@nestjs/config';

export default registerAs('redis', () => ({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  // Sử dụng biến RBAC_CACHE_TTL từ .env của bạn
  ttl: parseInt(process.env.RBAC_CACHE_TTL || '300', 10),
  max: parseInt(process.env.RBAC_CACHE_MAX || '1000', 10),
}));
```

## File: src/config/event-bus.config.ts
```
import { registerAs } from '@nestjs/config';

export default registerAs('eventBus', () => ({
  // 'memory' | 'rabbitmq' | 'kafka'
  type: process.env.EVENT_BUS_TYPE || 'memory',
}));
```

## File: src/config/dental.config.ts
```
import { registerAs } from '@nestjs/config';

export default registerAs('dental', () => ({
  // Upload & Storage Paths
  uploadDir: process.env.DENTAL_UPLOAD_DIR || 'uploads/dental/temp',
  outputDir: process.env.DENTAL_OUTPUT_DIR || 'uploads/dental/converted',

  // Encryption
  encryptionKey:
    process.env.DENTAL_ENCRYPTION_KEY || 'qW9xZ2tL8mP4rN6vB3jF5hY7cT2kD9wE', // 32 chars

  // Conversion Settings
  simplificationRatio: 0.3,
  errorThreshold: 0.0005,
  timeout: 300000, // 5 mins

  // Worker Pool
  minThreads: parseInt(process.env.PISCINA_MIN_THREADS || '0', 10),
  maxThreads: parseInt(process.env.PISCINA_MAX_THREADS || '0', 10),
}));
```

## File: src/database/schema/index.ts
```
export * from './users.schema';
export * from './sessions.schema';
export * from './rbac.schema';
export * from './notifications.schema';
export * from './ortho.schema';
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
    createdAt: timestamp('createdAt').defaultNow().notNull(),
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

// --- 1. TABLES DEFINITIONS ---

// Permissions Table
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

// Roles Table
export const roles = pgTable('roles', {
  id: serial('id').primaryKey(),
  name: text('name').notNull().unique(),
  description: text('description'),
  isActive: boolean('isActive').default(true),
  isSystem: boolean('isSystem').default(false),
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
});

// User Roles (Pivot Table: Users <-> Roles)
export const userRoles = pgTable(
  'user_roles',
  {
    userId: bigint('userId', { mode: 'number' }).notNull(),
    roleId: integer('roleId') // Lưu ý: DB column name nên để 'role_id' nếu muốn chuẩn snake_case, ở đây giữ nguyên theo code cũ của bạn
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

// Role Permissions (Pivot Table: Roles <-> Permissions)
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

// --- 2. RELATIONS DEFINITIONS ---

// Relations cho Permissions
export const permissionsRelations = relations(permissions, ({ many }) => ({
  roles: many(rolePermissions), // Permission có nhiều entry trong bảng nối rolePermissions
}));

// Relations cho Roles
export const rolesRelations = relations(roles, ({ many }) => ({
  permissions: many(rolePermissions), // Role có nhiều entry trong bảng nối rolePermissions
  // Nếu bạn muốn query ngược từ Role ra User, cần relation này (Optional)
  users: many(userRoles),
}));

// Relations cho RolePermissions (Bảng nối)
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

// Relations cho UserRoles (Bảng nối) - PHẦN BỊ THIẾU GÂY LỖI
export const userRolesRelations = relations(userRoles, ({ one }) => ({
  role: one(roles, {
    fields: [userRoles.roleId],
    references: [roles.id],
  }),
  // Chúng ta chưa import bảng 'users' ở đây để tránh Circular Dependency.
  // Nếu cần query user từ bảng nối này, cần import 'users' cẩn thận.
  // Hiện tại chỉ cần 'role' để Drizzle hiểu graph khi query từ Role.
}));
```

## File: src/database/schema/notifications.schema.ts
```
import {
  pgTable,
  serial,
  text,
  timestamp,
  integer,
  boolean,
} from 'drizzle-orm/pg-core';

export const notifications = pgTable('notifications', {
  id: serial('id').primaryKey(),
  userId: integer('userId').notNull(), // Liên kết lỏng với bảng Users
  type: text('type').notNull(), // EMAIL, SMS
  subject: text('subject').notNull(),
  content: text('content').notNull(),
  status: text('status').notNull(), // PENDING, SENT
  sentAt: timestamp('sentAt'),
  createdAt: timestamp('createdAt').defaultNow(),
});
```

## File: src/database/schema/ortho.schema.ts
```
import {
  pgTable,
  serial,
  text,
  timestamp,
  integer,
  jsonb,
  date,
  boolean,
  index,
  pgEnum,
  numeric,
  bigint,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from './users.schema'; // Link với bảng Users có sẵn

// --- 1. ENUMS (Khớp với nghiệp vụ) ---
export const genderEnum = pgEnum('gender', ['Male', 'Female', 'Other']);
export const productTypeEnum = pgEnum('product_type', ['retainer', 'aligner']);
export const jawTypeEnum = pgEnum('jaw_type', ['Upper', 'Lower']);

// --- 2. BẢNG CLINICS (Phòng khám) ---
export const clinics = pgTable('clinics', {
  id: serial('id').primaryKey(),
  // Dùng bigint vì users.id thường là bigserial
  userId: bigint('user_id', { mode: 'number' }).references(() => users.id),
  name: text('name').notNull(),
  clinicCode: text('clinic_code').notNull().unique(), // VD: NK1
  address: text('address'),
  phoneNumber: text('phone_number'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// --- 3. BẢNG DENTISTS (Bác sĩ) ---
export const dentists = pgTable('dentists', {
  id: serial('id').primaryKey(),
  userId: bigint('user_id', { mode: 'number' }).references(() => users.id),
  clinicId: integer('clinic_id').references(() => clinics.id),
  fullName: text('full_name').notNull(),
  phoneNumber: text('phone_number'),
  email: text('email'),
  createdAt: timestamp('created_at').defaultNow(),
});

// --- 4. BẢNG PATIENTS (Bệnh nhân) ---
export const patients = pgTable('patients', {
  id: serial('id').primaryKey(),
  clinicId: integer('clinic_id').references(() => clinics.id),
  userId: bigint('user_id', { mode: 'number' }).references(() => users.id),

  patientCode: text('patient_code').notNull().unique(), // VD: #NK121789
  fullName: text('full_name').notNull(),
  email: text('email'),
  phoneNumber: text('phone_number'),
  address: text('address'),
  birthDate: date('date_of_birth'),
  gender: genderEnum('gender'),

  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// --- 5. BẢNG CASES (Ca điều trị) ---
export const cases = pgTable('cases', {
  id: serial('id').primaryKey(),
  orderId: text('order_id').unique(), // ORD-2510...

  patientId: integer('patient_id')
    .references(() => patients.id)
    .notNull(),
  dentistId: integer('dentist_id').references(() => dentists.id),

  productType: productTypeEnum('product_type').notNull(),
  status: text('status').default('PLANNING'),

  notes: text('notes'),
  price: numeric('price', { precision: 12, scale: 2 }),

  scanDate: timestamp('scan_date'),
  dateDue: timestamp('date_due'),
  startedAt: timestamp('started_at'),

  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// --- 6. BẢNG TREATMENT STEPS (Lưu trữ dữ liệu 3D - JSONB) ---
export const treatmentSteps = pgTable(
  'treatment_steps',
  {
    id: serial('id').primaryKey(),
    caseId: integer('case_id')
      .references(() => cases.id)
      .notNull(),
    stepIndex: integer('step_index').notNull(), // 0, 1, 2...

    // JSONB chứa toàn bộ thông số di chuyển (Torque, Angulation...)
    teethData: jsonb('teeth_data').notNull(),

    hasIpr: boolean('has_ipr').default(false),
    hasAttachments: boolean('has_attachments').default(false),

    createdAt: timestamp('created_at').defaultNow(),
  },
  (table) => ({
    caseStepIdx: index('idx_case_step').on(table.caseId, table.stepIndex),
  }),
);

// --- RELATIONS ---
export const clinicsRelations = relations(clinics, ({ one, many }) => ({
  manager: one(users, { fields: [clinics.userId], references: [users.id] }),
  dentists: many(dentists),
  patients: many(patients),
}));

export const dentistsRelations = relations(dentists, ({ one, many }) => ({
  user: one(users, { fields: [dentists.userId], references: [users.id] }),
  clinic: one(clinics, {
    fields: [dentists.clinicId],
    references: [clinics.id],
  }),
  cases: many(cases),
}));

export const patientsRelations = relations(patients, ({ one, many }) => ({
  clinic: one(clinics, {
    fields: [patients.clinicId],
    references: [clinics.id],
  }),
  user: one(users, { fields: [patients.userId], references: [users.id] }),
  cases: many(cases),
}));

export const casesRelations = relations(cases, ({ one, many }) => ({
  patient: one(patients, {
    fields: [cases.patientId],
    references: [patients.id],
  }),
  dentist: one(dentists, {
    fields: [cases.dentistId],
    references: [dentists.id],
  }),
  steps: many(treatmentSteps),
}));

export const treatmentStepsRelations = relations(treatmentSteps, ({ one }) => ({
  case: one(cases, { fields: [treatmentSteps.caseId], references: [cases.id] }),
}));
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

## File: src/api/middleware/request-logging.middleware.ts
```
import { Injectable, NestMiddleware, Inject } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import type { ILogger } from '@core/shared/application/ports/logger.port';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import {
  RequestContextService,
  RequestContext,
} from '@core/shared/infrastructure/context/request-context.service';

@Injectable()
export class RequestLoggingMiddleware implements NestMiddleware {
  constructor(@Inject(LOGGER_TOKEN) private readonly logger: ILogger) {}

  use(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();

    let rawRequestId = req.headers['x-request-id'];
    if (Array.isArray(rawRequestId)) rawRequestId = rawRequestId[0];
    const requestId = rawRequestId || `req-${Date.now()}`;

    req.headers['x-request-id'] = requestId;
    res.setHeader('x-request-id', requestId);

    // QUAN TRỌNG: Bọc next() trong RequestContextService.run
    const context = new RequestContext(requestId, req.originalUrl);

    RequestContextService.run(context, () => {
      // Log lúc bắt đầu (bên trong context)
      this.logger.info(`Incoming Request: ${req.method} ${req.originalUrl}`, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      res.on('finish', () => {
        const duration = Date.now() - startTime;
        const statusCode = res.statusCode;
        const message = `Request Completed: ${statusCode} (${duration}ms)`;
        const logContext = { statusCode, duration };

        if (statusCode >= 500) {
          this.logger.error(message, undefined, logContext);
        } else if (statusCode >= 400) {
          this.logger.warn(message, logContext);
        } else {
          this.logger.info(message, logContext);
        }
      });

      next();
    });
  }
}
```

