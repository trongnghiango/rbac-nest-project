// src/modules/rbac/infrastructure/decorators/permission.decorator.ts
import { SetMetadata } from '@nestjs/common';
import { PermissionString } from '../../domain/constants/rbac.constants'; // ✅ Import type

export const PERMISSIONS_KEY = 'permissions';

// ✅ Ép kiểu ...permissions thành mảng PermissionString
export const Permissions = (...permissions: PermissionString[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);