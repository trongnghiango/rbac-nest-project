#!/bin/bash

# ============================================
# FIX IMPORT PATH IN ROLE DTO
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🛠️ FIXING ROLE DTO IMPORT PATHS (2 DOTS)..."

cat > src/modules/rbac/infrastructure/dtos/role.dto.ts << 'EOF'
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

    dto.permissions = role.permissions ? role.permissions.map(p => ({
      id: p.id!,
      name: p.name,
      description: p.description || '',
      resourceType: p.resourceType || '',
      action: p.action || '',
    })) : [];

    return dto;
  }
}
EOF

success "✅ DTO PATHS FIXED!"
echo "👉 App should compile cleanly now."