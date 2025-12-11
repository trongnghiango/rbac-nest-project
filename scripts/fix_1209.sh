#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
ensure_dir() { mkdir -p "$@"; }

log "🛠️ FIXING SECURITY, VALIDATION AND EXCEPTION HANDLING..."

# ============================================
# 1. FIX EXCEPTION HANDLING (SERVICE LAYER)
# ============================================
log "1. Fixing Exception Handling (500 -> 400/401/404)..."

# Sửa AuthenticationService: Dùng Exception chuẩn của NestJS
cat > src/modules/auth/application/services/authentication.service.ts << 'EOF'
import { Injectable, Inject, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import { PasswordUtil } from '../../../shared/utils/password.util';
import { User } from '../../../user/domain/entities/user.entity';
import { JwtPayload } from '../../../shared/types/common.types';

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject('IUserRepository') private userRepository: IUserRepository,
    private jwtService: JwtService,
  ) {}

  async login(credentials: { username: string; password: string }): Promise<{ accessToken: string; user: any }> {
    const user = await this.userRepository.findByUsername(credentials.username);

    // FIX: Throw UnauthorizedException instead of generic Error
    if (!user || !user.isActive) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.hashedPassword) {
      throw new UnauthorizedException('Password not set for this user');
    }

    const isValid = await PasswordUtil.compare(credentials.password, user.hashedPassword);

    if (!isValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload: JwtPayload = {
      sub: user.id,
      username: user.username,
      roles: [],
    };

    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      user: user.toJSON(),
    };
  }

  async validateUser(payload: JwtPayload): Promise<ReturnType<User['toJSON']> | null> {
    const user = await this.userRepository.findById(payload.sub);
    if (!user || !user.isActive) {
      return null;
    }
    return user.toJSON();
  }

  async register(data: any): Promise<{ accessToken: string; user: any }> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) {
      // FIX: Throw BadRequestException
      throw new BadRequestException('User already exists');
    }

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

    const payload = {
      sub: savedUser.id,
      username: savedUser.username,
      roles: [],
    };
    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      user: savedUser.toJSON(),
    };
  }
}
EOF

# Sửa UserService: Dùng NotFoundException
cat > src/modules/user/application/services/user.service.ts << 'EOF'
import { Injectable, Inject, NotFoundException, BadRequestException } from '@nestjs/common';
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
    Object.assign(newUser, { ...data, hashedPassword, isActive: true, createdAt: new Date(), updatedAt: new Date() });

    const user = await this.userRepository.save(newUser);
    return user.toJSON();
  }

  async validateCredentials(username: string, pass: string): Promise<User | null> {
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

  async updateUserProfile(userId: number, profileData: any): Promise<ReturnType<User['toJSON']>> {
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
EOF

# ============================================
# 2. FIX SECURITY (RBAC GUARD)
# ============================================
log "2. Fixing Security Hole (Adding PermissionGuard)..."

# Sửa RoleController: Thêm PermissionGuard vào UseGuards
cat > src/modules/rbac/infrastructure/controllers/role.controller.ts << 'EOF'
import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { RoleService } from '../../application/services/role.service';
import { PermissionService } from '../../application/services/permission.service';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../guards/permission.guard'; // Import Guard
import { Permissions } from '../decorators/permission.decorator';

@Controller('rbac/roles')
// FIX: Add PermissionGuard here. Without it, @Permissions decorator is useless!
@UseGuards(JwtAuthGuard, PermissionGuard)
export class RoleController {
  constructor(
    private roleService: RoleService,
    private permissionService: PermissionService,
  ) {}

  @Get()
  @Permissions('rbac:manage')
  async getAllRoles() {
    return { message: 'Get all roles' };
  }

  @Post('assign')
  @Permissions('rbac:manage')
  async assignRole(@Body() body: { userId: number; roleId: number }) {
    await this.permissionService.assignRole(body.userId, body.roleId, 1);
    return { success: true, message: 'Role assigned' };
  }
}
EOF

# ============================================
# 3. FIX VALIDATION (CREATE DTO)
# ============================================
log "3. Fixing Validation (Creating DTOs)..."

ensure_dir src/modules/user/infrastructure/dtos

# Tạo DTO để validate Update Profile
cat > src/modules/user/infrastructure/dtos/update-profile.dto.ts << 'EOF'
import { IsString, IsOptional, IsUrl, IsEnum, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

class SocialLinksDto {
  @IsOptional() @IsUrl() facebook?: string;
  @IsOptional() @IsUrl() telegram?: string;
  @IsOptional() @IsUrl() website?: string;
}

class SettingsDto {
  @IsOptional() @IsEnum(['dark', 'light']) theme: 'dark' | 'light';
  @IsOptional() notifications: boolean;
}

export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  bio?: string;

  @IsOptional()
  @IsString()
  birthday?: string;

  @IsOptional()
  @IsUrl()
  avatarUrl?: string;

  @IsOptional()
  @IsEnum(['male', 'female', 'other'])
  gender?: 'male' | 'female' | 'other';

  @IsOptional()
  @ValidateNested()
  @Type(() => SocialLinksDto)
  socialLinks?: SocialLinksDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => SettingsDto)
  settings?: SettingsDto;
}
EOF

# Sửa UserController: Sử dụng DTO thay vì any
cat > src/modules/user/infrastructure/controllers/user.controller.ts << 'EOF'
import { Controller, Get, Param, Put, Body, UseGuards } from '@nestjs/common';
import { UserService } from '../../application/services/user.service';
import { CurrentUser } from '../../../auth/infrastructure/decorators/current-user.decorator';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { User } from '../../domain/entities/user.entity';
import { UpdateProfileDto } from '../dtos/update-profile.dto'; // Import DTO

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UserController {
  constructor(private userService: UserService) {}

  @Get('profile')
  async getProfile(@CurrentUser() user: User) {
    return this.userService.getUserById(user.id);
  }

  @Put('profile')
  // FIX: Use UpdateProfileDto instead of any. This triggers ValidationPipe.
  async updateProfile(@CurrentUser() user: User, @Body() profileData: UpdateProfileDto) {
    return this.userService.updateUserProfile(user.id, profileData);
  }

  @Get(':id')
  async getUserById(@Param('id') id: number) {
    return this.userService.getUserById(id);
  }
}
EOF

# ============================================
# 4. FIX AuthController VALIDATION
# ============================================
ensure_dir src/modules/auth/infrastructure/dtos

cat > src/modules/auth/infrastructure/dtos/auth.dto.ts << 'EOF'
import { IsString, MinLength, IsNumber, IsOptional, IsEmail } from 'class-validator';

export class LoginDto {
  @IsString()
  username: string;

  @IsString()
  @MinLength(6)
  password: string;
}

export class RegisterDto {
  @IsNumber()
  id: number;

  @IsString()
  username: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsString()
  fullName: string;

  @IsOptional()
  @IsEmail()
  email?: string;
}
EOF

cat > src/modules/auth/infrastructure/controllers/auth.controller.ts << 'EOF'
import { Controller, Post, Body, UseGuards, Get } from '@nestjs/common';
import { AuthenticationService } from '../../application/services/authentication.service';
import { Public } from '../decorators/public.decorator';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { User } from '../../../user/domain/entities/user.entity';
import { LoginDto, RegisterDto } from '../dtos/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthenticationService) {}

  @Public()
  @Post('login')
  async login(@Body() credentials: LoginDto) {
    return this.authService.login(credentials);
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
EOF

echo "✅ DONE! All critical issues fixed."
echo "👉 1. Guards added to RBAC Controller (Security Fix)"
echo "👉 2. DTOs added to Controllers (Validation Fix)"
echo "👉 3. Proper Exceptions in Services (Error Handling Fix)"
echo "PLEASE RESTART SERVER: docker-compose up -d --build"
