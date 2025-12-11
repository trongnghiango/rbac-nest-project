## File: src/bootstrap/app.module.ts
```
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';

// Configs
import databaseConfig from '../config/database.config';
import appConfig from '../config/app.config';
import loggingConfig from '../config/logging.config';

// Core & Shared
import { CoreModule } from '../core/core.module';
import { SharedModule } from '../modules/shared/shared.module';

// Feature Modules
import { UserModule } from '../modules/user/user.module';
import { AuthModule } from '../modules/auth/auth.module';
import { RbacModule } from '../modules/rbac/rbac.module';
import { TestModule } from '../modules/test/test.module';

@Module({
  imports: [
    // 1. Config
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      load: [databaseConfig, appConfig, loggingConfig],
    }),

    // 2. Core (Global Pipes/Filters/Interceptors)
    CoreModule,
    SharedModule,

    // 3. Database
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        ...config.get('database'),
        entities: [__dirname + '/../**/*.entity{.ts,.js}'],
        autoLoadEntities: true,
      }),
      inject: [ConfigService],
    }),

    // 4. Cache
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: () => ({ ttl: 300, max: 100 }),
      inject: [ConfigService],
    }),

    // 5. Features
    UserModule,
    AuthModule,
    RbacModule,
    TestModule, // Uncommented TestModule for testing
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

  const prefix = config.get('app.apiPrefix', 'api');
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

  const port = config.get('app.port', 3000);
  await app.listen(port);

  console.log(`🚀 API is running on: http://localhost:${port}/${prefix}`);
  console.log(`📚 Swagger Docs:      http://localhost:${port}/docs`);
  console.log(`📊 Health check:      http://localhost:${port}/${prefix}/test/health`);
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
bootstrap().catch((err) => console.error('Err::', err['message']));
```

## File: src/modules/auth/domain/entities/session.entity.ts
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
@Index('idx_sessions_expires_at', ['expiresAt'])
export class Session {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('bigint')
  userId: number;

  @Column()
  token: string;

  @Column({ type: 'timestamptz' })
  expiresAt: Date;

  @Column({ nullable: true })
  ipAddress: string;

  @Column({ nullable: true })
  userAgent: string;

  @CreateDateColumn()
  createdAt: Date;

  isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  isValid(): boolean {
    return !this.isExpired();
  }
}
```

## File: src/modules/auth/application/services/authentication.service.ts
```
import { Injectable, Inject, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm'; // Import thêm cái này
import { Repository } from 'typeorm';               // Import thêm cái này
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import { PasswordUtil } from '../../../shared/utils/password.util';
import { User } from '../../../user/domain/entities/user.entity';
import { Session } from '../../domain/entities/session.entity'; // Import Session Entity
import { JwtPayload } from '../../../shared/types/common.types';

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject('IUserRepository') private userRepository: IUserRepository,
    // Inject thêm Repository của Session
    @InjectRepository(Session) private sessionRepository: Repository<Session>,
    private jwtService: JwtService,
  ) {}

  async login(credentials: { username: string; password: string; ip?: string; userAgent?: string }): Promise<{ accessToken: string; user: any }> {
    const user = await this.userRepository.findByUsername(credentials.username);

    if (!user || !user.isActive) throw new UnauthorizedException('Invalid credentials');
    if (!user.hashedPassword) throw new UnauthorizedException('Password not set');

    const isValid = await PasswordUtil.compare(credentials.password, user.hashedPassword);
    if (!isValid) throw new UnauthorizedException('Invalid credentials');

    // 1. Tạo JWT Access Token
    const payload: JwtPayload = {
      sub: user.id,
      username: user.username,
      roles: [],
    };
    const accessToken = this.jwtService.sign(payload);

    // 2. LƯU SESSION VÀO DB (Kích hoạt bảng sessions)
    // Tính thời gian hết hạn (ví dụ 1 ngày)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 1);

    const session = this.sessionRepository.create({
      userId: user.id,
      token: accessToken, // Hoặc lưu Refresh Token nếu dùng cơ chế Refresh
      ipAddress: credentials.ip || 'unknown',
      userAgent: credentials.userAgent || 'unknown',
      expiresAt: expiresAt,
      createdAt: new Date(),
    });

    await this.sessionRepository.save(session);

    return {
      accessToken,
      user: user.toJSON(),
    };
  }

  // ... (Các hàm validateUser, register giữ nguyên như cũ)
  async validateUser(payload: JwtPayload): Promise<ReturnType<User['toJSON']> | null> {
    const user = await this.userRepository.findById(payload.sub);

    // NÂNG CAO: Có thể check thêm session trong DB xem còn tồn tại không
    // Nếu admin đã xóa session thì dù token còn hạn cũng trả về null -> Đá user ra

    if (!user || !user.isActive) return null;
    return user.toJSON();
  }

  async register(data: any): Promise<{ accessToken: string; user: any }> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) throw new BadRequestException('User already exists');

    const hashedPassword = await PasswordUtil.hash(data.password);
    const user: any = {
      id: data.id,
      username: data.username,
      email: data.email,
      hashedPassword: hashedPassword,
      fullName: data.fullName,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const savedUser = await this.userRepository.save(user);

    // Khi register xong cũng tạo session luôn
    const payload = { sub: savedUser.id, username: savedUser.username, roles: [] };
    const accessToken = this.jwtService.sign(payload);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 1);

    await this.sessionRepository.save({
        userId: savedUser.id,
        token: accessToken,
        expiresAt: expiresAt,
        createdAt: new Date()
    });

    return { accessToken, user: savedUser.toJSON() };
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
import { IsString, MinLength, IsNumber, IsOptional, IsEmail } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'superadmin', description: 'Username for login' })
  @IsString()
  username: string;

  @ApiProperty({ example: 'SuperAdmin123!', description: 'Password (min 6 chars)' })
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
import { Session } from './domain/entities/session.entity';

@Module({
  imports: [
    UserModule,
    TypeOrmModule.forFeature([Session]),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET') || 'super-secret-key',
        signOptions: {
          expiresIn: configService.get('JWT_EXPIRES_IN', '24h'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthenticationService, JwtStrategy, JwtAuthGuard],
  exports: [JwtAuthGuard, AuthenticationService, JwtModule, PassportModule],
})
export class AuthModule {}
```

## File: src/modules/user/domain/entities/user.entity.ts
```
import {
  Entity,
  Column,
  PrimaryColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import type { UserProfile } from '../types/user-profile.type';

@Entity('users')
export class User {
  @PrimaryColumn('bigint')
  id: number; // Telegram ID or custom ID

  @Column({ unique: true })
  username: string;

  @Column({ unique: true, nullable: true })
  email?: string;

  @Column({ nullable: true })
  hashedPassword?: string;

  @Column()
  fullName: string;

  @Column({ default: true })
  isActive: boolean;

  @Column({ nullable: true })
  phoneNumber?: string;

  @Column({ nullable: true })
  avatarUrl?: string;

  @Column({ type: 'jsonb', nullable: true }) // Đổi simple-json -> jsonb (Postgres only)
  profile?: UserProfile;
  // @Column('simple-json', { nullable: true })
  // profile?: any;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Domain methods
  updateProfile(profileData: UserProfile): void {
    this.profile = { ...this.profile, ...profileData };
    this.updatedAt = new Date();
  }

  setPassword(password: string): void {
    // Password hashing should be done in application service
    this.hashedPassword = password; // Will be hashed by service
    this.updatedAt = new Date();
  }

  deactivate(): void {
    this.isActive = false;
    this.updatedAt = new Date();
  }

  activate(): void {
    this.isActive = true;
    this.updatedAt = new Date();
  }

  toJSON() {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { hashedPassword, ...rest } = this;
    return rest;
  }
}
```

## File: src/modules/user/domain/repositories/user-repository.interface.ts
```
import { User } from '../entities/user.entity';

export interface IUserRepository {
  findById(id: number): Promise<User | null>;
  findByUsername(username: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  findAllActive(): Promise<User[]>;
  save(user: User): Promise<User>;
  update(id: number, data: Partial<User>): Promise<User>;
  delete(id: number): Promise<void>;
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

  async createUser(data: any): Promise<any> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) {
      throw new BadRequestException('User already exists');
    }

    let hashedPassword;
    if (data.password) {
      if (!PasswordUtil.validateStrength(data.password)) {
        throw new BadRequestException('Password is too weak');
      }
      hashedPassword = await PasswordUtil.hash(data.password);
    }

    const newUser = new User();
    Object.assign(newUser, {
      ...data,
      hashedPassword,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const user = await this.userRepository.save(newUser);
    return user.toJSON();
  }

  async validateCredentials(
    username: string,
    pass: string,
  ): Promise<User | null> {
    // Keep internal logic as is, exceptions handled in AuthService
    const user = await this.userRepository.findByUsername(username);
    if (!user || !user.isActive || !user.hashedPassword) return null;
    const isValid = await PasswordUtil.compare(pass, user.hashedPassword);
    return isValid ? user : null;
  }

  async getUserById(id: number): Promise<ReturnType<User['toJSON']>> {
    const user = await this.userRepository.findById(id);
    if (!user) {
      // FIX: Throw NotFoundException
      throw new NotFoundException(`User with ID ${id} not found`);
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
```

## File: src/modules/user/infrastructure/controllers/user.controller.ts
```
import { Controller, Get, Param, Put, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { UserService } from '../../application/services/user.service';
import { CurrentUser } from '../../../auth/infrastructure/decorators/current-user.decorator';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { User } from '../../domain/entities/user.entity';
import { UpdateProfileDto } from '../dtos/update-profile.dto';

@ApiTags('Users')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('users')
export class UserController {
  constructor(private userService: UserService) {}

  @ApiOperation({ summary: 'Get current user profile' })
  @Get('profile')
  async getProfile(@CurrentUser() user: User) {
    return this.userService.getUserById(user.id);
  }

  @ApiOperation({ summary: 'Update user profile' })
  @Put('profile')
  async updateProfile(@CurrentUser() user: User, @Body() profileData: UpdateProfileDto) {
    return this.userService.updateUserProfile(user.id, profileData);
  }

  @ApiOperation({ summary: 'Get user by ID (Admin/Manager)' })
  @Get(':id')
  async getUserById(@Param('id') id: number) {
    return this.userService.getUserById(id);
  }
}
```

## File: src/modules/user/infrastructure/dtos/update-profile.dto.ts
```
import { IsString, IsOptional, IsUrl, IsEnum, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

class SocialLinksDto {
  @ApiPropertyOptional() @IsOptional() @IsUrl() facebook?: string;
  @ApiPropertyOptional() @IsOptional() @IsUrl() telegram?: string;
  @ApiPropertyOptional() @IsOptional() @IsUrl() website?: string;
}

class SettingsDto {
  @ApiPropertyOptional({ enum: ['dark', 'light'] })
  @IsOptional() @IsEnum(['dark', 'light']) theme: 'dark' | 'light';

  @ApiPropertyOptional()
  @IsOptional() notifications: boolean;
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
import { User } from './domain/entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
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
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToMany,
  JoinTable,
} from 'typeorm';
import { Permission } from './permission.entity';

@Entity('roles')
export class Role {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true, length: 50 })
  name: string;

  @Column({ nullable: true })
  description: string;

  @Column({ default: true })
  isActive: boolean;

  @Column({ default: false })
  isSystem: boolean;

  @ManyToMany(() => Permission)
  @JoinTable({
    name: 'role_permissions',
    joinColumn: { name: 'role_id', referencedColumnName: 'id' },
    inverseJoinColumn: { name: 'permission_id', referencedColumnName: 'id' },
  })
  permissions: Permission[];

  @CreateDateColumn()
  createdAt: Date;

  @CreateDateColumn()
  updatedAt: Date;

  hasPermission(permissionName: string): boolean {
    return this.permissions?.some((p) => p.name === permissionName) || false;
  }

  addPermission(permission: Permission): void {
    if (!this.permissions) this.permissions = [];
    if (!this.hasPermission(permission.name)) {
      this.permissions.push(permission);
    }
  }
}
```

## File: src/modules/rbac/domain/entities/permission.entity.ts
```
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';

@Entity('permissions')
export class Permission {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true, length: 100 })
  name: string;

  @Column({ nullable: true })
  description: string;

  @Column({ length: 50, nullable: true })
  resourceType: string;

  @Column({ length: 50, nullable: true })
  action: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;
}
```

## File: src/modules/rbac/domain/entities/user-role.entity.ts
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
import { Role } from './role.entity';

@Entity('user_roles')
@Index('idx_user_roles_user_id', ['userId'])
@Index('idx_user_roles_role_id', ['roleId'])
export class UserRole {
  @PrimaryColumn('bigint')
  userId: number;

  @PrimaryColumn('int')
  roleId: number;

  @Column('bigint', { nullable: true })
  assignedBy: number;

  @Column({ type: 'timestamptz', nullable: true })
  expiresAt: Date;

  @CreateDateColumn()
  assignedAt: Date;

  // Added relation for joins
  @ManyToOne(() => Role)
  @JoinColumn({ name: 'roleId' })
  role: Role;

  isActive(): boolean {
    if (!this.expiresAt) return true;
    return new Date() < this.expiresAt;
  }
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
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import type { Cache } from 'cache-manager';
import { UserRole } from '../../domain/entities/user-role.entity';
import { Role } from '../../domain/entities/role.entity';

@Injectable()
export class PermissionService {
  private readonly CACHE_TTL = 300; // 5 minutes
  private readonly CACHE_PREFIX = 'rbac:permissions:';

  constructor(
    @InjectRepository(UserRole)
    private userRoleRepository: Repository<UserRole>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async userHasPermission(
    userId: number,
    permissionName: string,
  ): Promise<boolean> {
    // Check cache first
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;
    const cached = await this.cacheManager.get<string[]>(cacheKey);

    if (cached) {
      return cached.includes(permissionName) || cached.includes('*');
    }

    // Get user's active roles
    // Join with role to ensure it exists and is valid
    const userRoles = await this.userRoleRepository.find({
      where: { userId },
      relations: ['role'],
    });

    const activeRoles = userRoles.filter(
      (ur) => ur.isActive() && ur.role.isActive,
    );
    const roleIds = activeRoles.map((ur) => ur.roleId);

    if (roleIds.length === 0) return false;

    // Get roles with permissions
    const roles = await this.roleRepository.find({
      where: { id: In(roleIds), isActive: true },
      relations: ['permissions'],
    });

    // Collect all permissions
    const permissions = new Set<string>();

    for (const role of roles) {
      if (role?.permissions) {
        role.permissions.forEach((p) => {
          if (p.isActive) {
            permissions.add(p.name);
          }
        });
      }
    }

    const permissionArray = Array.from(permissions);

    // Cache permissions
    await this.cacheManager.set(cacheKey, permissionArray, this.CACHE_TTL);

    return permissionArray.includes(permissionName);
  }

  async getUserPermissions(userId: number): Promise<string[]> {
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;

    // Try cache
    const cached = await this.cacheManager.get<string[]>(cacheKey);
    if (cached) return cached;

    // Query database
    const userRoles = await this.userRoleRepository.find({
      where: { userId },
      relations: ['role'],
    });

    const activeRoles = userRoles.filter((ur) => ur.isActive());
    const roleIds = activeRoles.map((ur) => ur.roleId);

    if (roleIds.length === 0) return [];

    const roles = await this.roleRepository.find({
      where: {
        id: In(roleIds),
        isActive: true,
      },
      relations: ['permissions'],
    });

    const permissions = new Set<string>();

    for (const role of roles) {
      if (role?.permissions) {
        role.permissions.forEach((p) => {
          if (p.isActive) {
            permissions.add(p.name);
          }
        });
      }
    }

    const permissionArray = Array.from(permissions);

    // Cache
    await this.cacheManager.set(cacheKey, permissionArray, this.CACHE_TTL);

    return permissionArray;
  }

  async getUserRoles(userId: number): Promise<string[]> {
    const userRoles = await this.userRoleRepository.find({
      where: { userId },
      relations: ['role'],
    });

    const activeRoles = userRoles.filter((ur) => ur.isActive());
    // Safe access to role name thanks to relation
    return activeRoles.map((ur) => ur.role.name);
  }

  async assignRole(
    userId: number,
    roleId: number,
    assignedBy: number,
  ): Promise<void> {
    const existing = await this.userRoleRepository.findOne({
      where: { userId, roleId },
    });

    if (existing) {
      throw new Error('User already has this role');
    }

    await this.userRoleRepository.save({
      userId,
      roleId,
      assignedBy,
      assignedAt: new Date(),
    });

    // Invalidate cache
    await this.cacheManager.del(`${this.CACHE_PREFIX}${userId}`);
  }

  async removeRole(userId: number, roleId: number): Promise<void> {
    await this.userRoleRepository.delete({ userId, roleId });
    await this.cacheManager.del(`${this.CACHE_PREFIX}${userId}`);
  }

  initializeDefaultData(): void {
    console.log('Initializing default RBAC data...');
  }
}
```

## File: src/modules/rbac/application/services/role.service.ts
```
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  SystemRole,
  SystemPermission,
} from '../../domain/constants/rbac.constants';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';

// 1. Thêm cái này ngay bên trên class RoleService hoặc đầu file
export interface AccessControlItem {
  role: string;
  resource: string;
  action: string;
  attributes: string;
}

@Injectable()
export class RoleService {
  constructor(
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
  ) {}

  async createRole(data: {
    name: string;
    description?: string;
    isSystem?: boolean;
  }): Promise<Role> {
    const existing = await this.roleRepository.findOne({
      where: { name: data.name },
    });

    if (existing) {
      throw new Error(`Role ${data.name} already exists`);
    }

    const role = this.roleRepository.create({
      name: data.name,
      description: data.description,
      isSystem: data.isSystem || false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    return this.roleRepository.save(role);
  }

  async assignPermissionToRole(
    roleId: number,
    permissionId: number,
  ): Promise<void> {
    const role = await this.roleRepository.findOne({
      where: { id: roleId },
      relations: ['permissions'],
    });

    if (!role) {
      throw new Error('Role not found');
    }

    const permission = await this.permissionRepository.findOne({
      where: { id: permissionId },
    });

    if (!permission) {
      throw new Error('Permission not found');
    }

    if (!role.permissions) role.permissions = [];

    const alreadyHas = role.permissions.some((p) => p.id === permissionId);
    if (!alreadyHas) {
      role.permissions.push(permission);
      role.updatedAt = new Date();
      await this.roleRepository.save(role);
    }
  }

  async getRoleWithPermissions(roleName: string): Promise<Role | null> {
    return this.roleRepository.findOne({
      where: { name: roleName },
      relations: ['permissions'],
    });
  }

  async initializeSystemRoles(): Promise<void> {
    const systemRoles = Object.values(SystemRole);

    for (const roleName of systemRoles) {
      const existing = await this.roleRepository.findOne({
        where: { name: roleName },
      });

      if (!existing) {
        await this.createRole({
          name: roleName,
          description: `System role: ${roleName}`,
          isSystem: true,
        });
      }
    }
  }

  async initializeSystemPermissions(): Promise<void> {
    const systemPermissions = Object.values(SystemPermission);

    for (const permName of systemPermissions) {
      const existing = await this.permissionRepository.findOne({
        where: { name: permName },
      });

      if (!existing) {
        const [resource, action] = permName.split(':');

        await this.permissionRepository.save({
          name: permName,
          description: `Permission: ${permName}`,
          resourceType: resource,
          action: action,
          isActive: true,
          createdAt: new Date(),
        });
      }
    }
  }

  async getAccessControlList(): Promise<AccessControlItem[]> {
    // Lấy Role kèm theo Permission
    const roles = await this.roleRepository.find({
      relations: ['permissions'],
      where: { isActive: true },
    });

    const accessControlList: AccessControlItem[] = [];

    roles.forEach((role) => {
      if (role.permissions) {
        role.permissions.forEach((permission) => {
          // Logic: Nếu là ADMIN thì full quyền (*), user thì bị giới hạn (ví dụ mẫu)
          // Anh có thể sửa logic if/else ở đây tùy ý mà ko cần sửa DB
          let attributes = '*';

          // Ví dụ: Hardcode rule cho vui (hoặc để mặc định '*' hết cũng được)
          if (role.name === 'USER' && permission.resourceType === 'video') {
            attributes = '*, !views';
          }

          accessControlList.push({
            role: role.name.toLowerCase(),
            resource: permission.resourceType || 'all',
            action: permission.action || 'manage',
            attributes: attributes, // Giá trị tạo ra từ code
          });
        });
      }
    });

    return accessControlList;
  }
}
```

## File: src/modules/rbac/application/services/rbac-manager.service.ts
```
import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';

@Injectable()
export class RbacManagerService {
  private readonly logger = new Logger(RbacManagerService.name);

  constructor(
    @InjectRepository(Role)
    private roleRepo: Repository<Role>,
    @InjectRepository(Permission)
    private permRepo: Repository<Permission>,
  ) {}

  // ==========================================
  // 1. CHỨC NĂNG IMPORT (UPLOAD)
  // ==========================================
  async importFromCsv(
    csvContent: string,
  ): Promise<{ created: number; updated: number }> {
    const lines = csvContent
      .split(/\r?\n/)
      .filter((line) => line.trim() !== '');
    // Bỏ dòng header nếu có
    if (lines[0].toLowerCase().includes('role')) {
      lines.shift();
    }

    let createdCount = 0;
    let updatedCount = 0;

    for (const line of lines) {
      // CSV format: role,resource,action,attributes,description
      const cols = line.split(',').map((c) => c.trim());

      if (cols.length < 3) continue;

      // Vẫn lấy biến attributes ra nhưng không dùng để lưu vào DB (vì DB ko có cột này)
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const [roleName, resource, action, _attributes, description] = cols;

      // 1. Xử lý Permission
      const permName =
        resource === '*' ? 'manage:all' : `${resource}:${action}`;
      let perm = await this.permRepo.findOne({ where: { name: permName } });

      if (!perm) {
        // Fix TS2769: Bỏ field 'attributes' khi create
        perm = this.permRepo.create({
          name: permName,
          resourceType: resource,
          action: action,
          description: description || '',
          isActive: true,
        });
        await this.permRepo.save(perm);
        createdCount++;
      } else {
        // Fix TS2339: Chỉ update description, bỏ qua attributes
        let isChanged = false;
        if (description && perm.description !== description) {
          perm.description = description;
          isChanged = true;
        }

        if (isChanged) {
          await this.permRepo.save(perm);
          updatedCount++;
        }
      }

      // 2. Xử lý Role
      let role = await this.roleRepo.findOne({
        where: { name: roleName },
        relations: ['permissions'],
      });

      if (!role) {
        role = this.roleRepo.create({
          name: roleName,
          description: 'Imported from CSV',
          isActive: true,
          permissions: [],
        });
        await this.roleRepo.save(role);
      }

      // 3. Gán quyền vào Role
      if (!role.permissions) role.permissions = [];
      // Fix ESLint unnecessary assertion: perm chắc chắn tồn tại ở đây
      const hasPerm = role.permissions.some((p) => p.id === perm.id);

      if (!hasPerm) {
        role.permissions.push(perm);
        await this.roleRepo.save(role);
      }
    }

    this.logger.log(
      `Import finished. Created: ${createdCount}, Updated: ${updatedCount}`,
    );
    return { created: createdCount, updated: updatedCount };
  }

  // ==========================================
  // 2. CHỨC NĂNG EXPORT (DOWNLOAD)
  // ==========================================
  async exportToCsv(): Promise<string> {
    const roles = await this.roleRepo.find({
      relations: ['permissions'],
      order: { name: 'ASC' },
    });

    let csvContent = 'role,resource,action,attributes,description\n';

    for (const role of roles) {
      if (!role.permissions || role.permissions.length === 0) {
        csvContent += `${role.name},,,,\n`;
        continue;
      }

      for (const perm of role.permissions) {
        const desc =
          perm.description && perm.description.includes(',')
            ? `"${perm.description}"`
            : perm.description || '';

        const line = [
          role.name,
          perm.resourceType || '*',
          perm.action || '*',
          '*', // Fix TS2339: Hardcode attributes là '*' vì DB không lưu
          desc,
        ].join(',');

        csvContent += line + '\n';
      }
    }

    return csvContent;
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
        roleId: { type: 'number', example: 2 }
      }
    }
  })
  @Post('assign')
  @Permissions('rbac:manage')
  async assignRole(@Body() body: { userId: number; roleId: number }) {
    await this.permissionService.assignRole(
      body.userId,
      body.roleId,
      1,
    );
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
import { ApiTags, ApiOperation, ApiBearerAuth, ApiConsumes, ApiBody } from '@nestjs/swagger';
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

## File: src/modules/rbac/rbac.module.ts
```
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { UserModule } from '../user/user.module';

import { PermissionService } from './application/services/permission.service';
import { RoleService } from './application/services/role.service';
import { PermissionGuard } from './infrastructure/guards/permission.guard';
import { RoleController } from './infrastructure/controllers/role.controller';

import { Role } from './domain/entities/role.entity';
import { Permission } from './domain/entities/permission.entity';
import { UserRole } from './domain/entities/user-role.entity';
import { RbacManagerController } from './infrastructure/controllers/rbac-manager.controller';
import { RbacManagerService } from './application/services/rbac-manager.service';

@Module({
  imports: [
    UserModule,
    TypeOrmModule.forFeature([Role, Permission, UserRole]),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        ttl: configService.get('RBAC_CACHE_TTL', 300),
        max: configService.get('RBAC_CACHE_MAX', 1000),
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [RoleController, RbacManagerController],
  providers: [
    PermissionService,
    RoleService,
    PermissionGuard,
    RbacManagerService,
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

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
  ],
  providers: [],
  exports: [ConfigModule],
})
export class SharedModule {}
```

## File: src/modules/test/seeders/database.seeder.ts
```
import { Injectable, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { User } from '../../user/domain/entities/user.entity';
import { Role } from '../../rbac/domain/entities/role.entity';
import { Permission } from '../../rbac/domain/entities/permission.entity';
import { UserRole } from '../../rbac/domain/entities/user-role.entity';

import {
  SystemPermission,
  SystemRole,
} from '../../rbac/domain/constants/rbac.constants';

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
    @InjectRepository(UserRole)
    private userRoleRepository: Repository<UserRole>,
  ) {}

  async onModuleInit() {
    // Only seed in development
    if (process.env.NODE_ENV !== 'development') {
      return;
    }

    console.log('Seeding database...');

    await this.seedPermissions();
    await this.seedRoles();
    await this.seedUsers();
    await this.assignRolePermissions();
    await this.assignUserRoles();

    console.log('Database seeded successfully!');
  }

  private async seedPermissions(): Promise<void> {
    const permissions = Object.values(SystemPermission).map((name) => {
      const [resource, action] = name.split(':');
      return this.permissionRepository.create({
        name,
        description: `System permission: ${name}`,
        resourceType: resource,
        action: action,
        isActive: true,
        createdAt: new Date(),
      });
    });

    // Save one by one to avoid duplicate errors
    for (const p of permissions) {
      const exists = await this.permissionRepository.findOne({
        where: { name: p.name },
      });
      if (!exists) {
        await this.permissionRepository.save(p);
      }
    }
    console.log(`Checked permissions`);
  }

  private async seedRoles(): Promise<void> {
    const roles = Object.values(SystemRole).map((name) => ({
      name,
      description: `System role: ${name}`,
      isSystem: true,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    }));

    for (const r of roles) {
      const exists = await this.roleRepository.findOne({
        where: { name: r.name },
      });
      if (!exists) {
        await this.roleRepository.save(r);
      }
    }
    console.log(`Checked roles`);
  }

  private async seedUsers(): Promise<void> {
    const users = [
      {
        id: 1001,
        username: 'superadmin',
        email: 'superadmin@example.com',
        hashedPassword: await bcrypt.hash('SuperAdmin123!', 10),
        fullName: 'Super Administrator',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 1002,
        username: 'admin',
        email: 'admin@example.com',
        hashedPassword: await bcrypt.hash('Admin123!', 10),
        fullName: 'Administrator',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 1003,
        username: 'manager',
        email: 'manager@example.com',
        hashedPassword: await bcrypt.hash('Manager123!', 10),
        fullName: 'Manager User',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 1004,
        username: 'staff',
        email: 'staff@example.com',
        hashedPassword: await bcrypt.hash('Staff123!', 10),
        fullName: 'Staff User',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 1005,
        username: 'user1',
        email: 'user1@example.com',
        hashedPassword: await bcrypt.hash('User123!', 10),
        fullName: 'Regular User 1',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 1006,
        username: 'user2',
        email: 'user2@example.com',
        hashedPassword: await bcrypt.hash('User123!', 10),
        fullName: 'Regular User 2',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];

    for (const u of users) {
      const exists = await this.userRepository.findOne({
        where: { username: u.username },
      });
      if (!exists) {
        await this.userRepository.save(u);
      }
    }
    console.log(`Checked users`);
  }

  private async assignRolePermissions(): Promise<void> {
    // Get all permissions
    const permissions = await this.permissionRepository.find();

    // Get all roles
    const roles = await this.roleRepository.find({
      relations: ['permissions'],
    });
    const roleMap = new Map(roles.map((r) => [r.name, r]));

    // SUPER_ADMIN gets all permissions
    const superAdmin = roleMap.get(SystemRole.SUPER_ADMIN);
    if (superAdmin) {
      superAdmin.permissions = permissions;
      await this.roleRepository.save(superAdmin);
    }

    // ADMIN gets most permissions (except system:config)
    const admin = roleMap.get(SystemRole.ADMIN);
    if (admin) {
      admin.permissions = permissions.filter(
        (p) => !p.name.includes('system:'),
      );
      await this.roleRepository.save(admin);
    }

    // MANAGER gets management permissions
    const manager = roleMap.get(SystemRole.MANAGER);
    if (manager) {
      const managerPermissions = permissions.filter(
        (p) =>
          p.name.includes('report:') ||
          p.name.includes('booking:manage') ||
          p.name.includes('user:read'),
      );
      manager.permissions = managerPermissions;
      await this.roleRepository.save(manager);
    }

    // STAFF gets operational permissions
    const staff = roleMap.get(SystemRole.STAFF);
    if (staff) {
      const staffPermissions = permissions.filter(
        (p) =>
          p.name.includes('booking:create') ||
          p.name.includes('booking:read') ||
          p.name.includes('booking:update') ||
          p.name.includes('payment:process'),
      );
      staff.permissions = staffPermissions;
      await this.roleRepository.save(staff);
    }

    // USER gets basic permissions
    const userRole = roleMap.get(SystemRole.USER);
    if (userRole) {
      userRole.permissions = permissions.filter(
        (p) =>
          p.name === SystemPermission.USER_READ ||
          p.name === SystemPermission.BOOKING_CREATE ||
          p.name === SystemPermission.BOOKING_READ ||
          p.name === SystemPermission.PAYMENT_PROCESS,
      );
      await this.roleRepository.save(userRole);
    }

    console.log('Assigned permissions to roles');
  }

  private async assignUserRoles(): Promise<void> {
    const roles = await this.roleRepository.find();
    const roleMap = new Map(roles.map((r) => [r.name, r.id]));

    const assignments = [
      { userId: 1001, roleName: SystemRole.SUPER_ADMIN },
      { userId: 1002, roleName: SystemRole.ADMIN },
      { userId: 1003, roleName: SystemRole.MANAGER },
      { userId: 1004, roleName: SystemRole.STAFF },
      { userId: 1005, roleName: SystemRole.USER },
      { userId: 1006, roleName: SystemRole.USER },
    ];

    for (const assignment of assignments) {
      const roleId = roleMap.get(assignment.roleName);
      if (roleId) {
        const exists = await this.userRoleRepository.findOne({
          where: { userId: assignment.userId, roleId },
        });
        if (!exists) {
          await this.userRoleRepository.save({
            userId: assignment.userId,
            roleId,
            assignedBy: 1001, // superadmin
            assignedAt: new Date(),
          });
        }
      }
    }

    console.log('Assigned roles to users');
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

import { User } from '../user/domain/entities/user.entity';
import { Role } from '../rbac/domain/entities/role.entity';
import { Permission } from '../rbac/domain/entities/permission.entity';
import { UserRole } from '../rbac/domain/entities/user-role.entity';

@Module({
  imports: [
    UserModule,
    RbacModule,
    TypeOrmModule.forFeature([User, Role, Permission, UserRole]),
  ],
  controllers: [TestController],
  providers: [DatabaseSeeder],
})
export class TestModule implements OnModuleInit {
  constructor(private databaseSeeder: DatabaseSeeder) {}

  async onModuleInit() {
    // Auto-seed on module initialization
    await this.databaseSeeder.onModuleInit();
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
export class TransformResponseInterceptor<T> implements NestInterceptor<T, any> {
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
  // Cấu hình chung cho cả 2 môi trường
  const commonConfig = {
    type: 'postgres',
    synchronize: process.env.NODE_ENV === 'development', // Tắt trên production nhé
    logging: process.env.NODE_ENV === 'development',
    autoLoadEntities: true,
  };

  // 1. Ưu tiên chế độ CLOUD (Neon, Render, Supabase...)
  // Nếu có biến DATABASE_URL thì dùng luôn chuỗi kết nối
  if (process.env.DATABASE_URL) {
    console.log('📡 Using Database Connection String (Cloud/Neon)');
    return {
      ...commonConfig,
      url: process.env.DATABASE_URL,
      // Neon và các cloud DB thường yêu cầu SSL
      ssl: {
        rejectUnauthorized: false, // Chấp nhận chứng chỉ SSL của Neon
      },
    };
  }

  // 2. Chế độ LOCAL (Fallback)
  console.log('💻 Using Local Database Configuration');
  return {
    ...commonConfig,
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_DATABASE || 'rbac_system',
    // Local thường không cần SSL
    ssl: process.env.DB_SSL === 'true',
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

