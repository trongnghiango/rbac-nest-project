Chào bạn, tôi sẽ trả lời chi tiết và cung cấp giải pháp trọn gói cho yêu cầu **Import/Export CSV cho RBAC**.

Trước hết, trả lời câu hỏi của bạn về cơ chế hoạt động:

1.  **Cơ chế Upload (Import):**
    *   Giải pháp tôi viết dưới đây hoạt động theo cơ chế **UPSERT (Update or Insert)**.
    *   **Nếu chưa có:** Hệ thống sẽ **Tạo mới** (Role hoặc Permission).
    *   **Nếu đã có:** Hệ thống sẽ **Cập nhật** thông tin (ví dụ: bạn sửa Description hoặc Attributes trong CSV thì Database sẽ cập nhật theo).
    *   *Lưu ý:* Nó **không xóa** những quyền cũ trong Database nếu trong CSV không có (để an toàn, tránh mất dữ liệu do file CSV thiếu).

2.  **Tính năng Download (Export):**
    *   Tôi sẽ viết thêm hàm để quét toàn bộ Database và xuất ra file `.csv` đúng định dạng. Bạn tải về, sửa trên Excel/Text Editor, rồi upload ngược lại.

Dưới đây là phần code bổ sung hoàn chỉnh (Tiếp tục từ phần Controller như bạn yêu cầu, nhưng tôi gộp Logic vào một Service quản lý chuyên biệt để code gọn hơn).

---

### Bước 1: Cài đặt Type cho Multer (Nếu chưa có)
Để upload file không bị lỗi đỏ TypeScript:
```bash
npm install -D @types/multer
```

### Bước 2: Tạo Service quản lý Import/Export
Tạo file: `src/modules/rbac/application/services/rbac-manager.service.ts`

Service này đảm nhiệm 2 việc: Đọc CSV nhét vào DB và Lấy DB nhét vào CSV.

```typescript
import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Role } from '../../domain/entities/role.entity';
import { Permission } from '../../domain/entities/permission.entity';
import { SystemRole } from '../../domain/constants/rbac.constants';

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
  async importFromCsv(csvContent: string): Promise<{ created: number; updated: number }> {
    const lines = csvContent.split(/\r?\n/).filter((line) => line.trim() !== '');
    // Bỏ dòng header nếu có (kiểm tra dòng đầu có chứa chữ 'role')
    if (lines[0].toLowerCase().includes('role')) {
      lines.shift();
    }

    let createdCount = 0;
    let updatedCount = 0;

    for (const line of lines) {
      // CSV format: role,resource,action,attributes,description
      // Ví dụ: ADMIN,video,create,*,Quyền tạo video
      const cols = line.split(',').map((c) => c.trim());
      
      if (cols.length < 3) continue; // Bỏ qua dòng lỗi

      const [roleName, resource, action, attributes, description] = cols;
      
      // 1. Xử lý Permission (Tạo hoặc Update)
      const permName = resource === '*' ? 'manage:all' : `${resource}:${action}`;
      let perm = await this.permRepo.findOne({ where: { name: permName } });

      if (!perm) {
        perm = this.permRepo.create({
          name: permName,
          resourceType: resource,
          action: action,
          description: description || '',
          attributes: attributes || '*', // Mặc định là * nếu trống
          isActive: true,
        });
        await this.permRepo.save(perm);
        createdCount++;
      } else {
        // Nếu đã có thì update description/attributes (nếu CSV có thay đổi)
        let isChanged = false;
        if (attributes && perm.attributes !== attributes) { perm.attributes = attributes; isChanged = true; }
        if (description && perm.description !== description) { perm.description = description; isChanged = true; }
        
        if (isChanged) {
          await this.permRepo.save(perm);
          updatedCount++;
        }
      }

      // 2. Xử lý Role (Tạo hoặc Update)
      let role = await this.roleRepo.findOne({ 
        where: { name: roleName },
        relations: ['permissions'] 
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

      // 3. Gán quyền vào Role (Nếu chưa có)
      if (!role.permissions) role.permissions = [];
      const hasPerm = role.permissions.some((p) => p.id === perm!.id);
      
      if (!hasPerm) {
        role.permissions.push(perm);
        await this.roleRepo.save(role);
      }
    }

    this.logger.log(`Import finished. Created: ${createdCount}, Updated: ${updatedCount}`);
    return { created: createdCount, updated: updatedCount };
  }

  // ==========================================
  // 2. CHỨC NĂNG EXPORT (DOWNLOAD)
  // ==========================================
  async exportToCsv(): Promise<string> {
    // Lấy toàn bộ Role và Permission của nó
    const roles = await this.roleRepo.find({
      relations: ['permissions'],
      order: { name: 'ASC' }
    });

    // Header của CSV
    let csvContent = 'role,resource,action,attributes,description\n';

    for (const role of roles) {
      if (!role.permissions || role.permissions.length === 0) {
        // Nếu role không có quyền gì, vẫn in ra 1 dòng để biết role tồn tại
        csvContent += `${role.name},,,,\n`;
        continue;
      }

      for (const perm of role.permissions) {
        // Format dòng: RoleName, Resource, Action, Attributes, Description
        // Cần xử lý dấu phẩy trong description nếu có (bọc ngoặc kép)
        const desc = perm.description && perm.description.includes(',') 
          ? `"${perm.description}"` 
          : (perm.description || '');

        const line = [
          role.name,
          perm.resourceType || '*',
          perm.action || '*',
          perm.attributes || '*', // Nếu bạn đã thêm cột attributes vào entity
          desc
        ].join(',');

        csvContent += line + '\n';
      }
    }

    return csvContent;
  }
}
```

### Bước 3: Tạo Controller Upload/Download

Tạo file: `src/modules/rbac/infrastructure/controllers/rbac-manager.controller.ts`

```typescript
import { 
  Controller, 
  Post, 
  Get, 
  UseInterceptors, 
  UploadedFile, 
  UseGuards, 
  BadRequestException, 
  Res,
  StreamableFile
} from '@nestjs/common';
import { Response } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../guards/permission.guard';
import { Permissions } from '../decorators/permission.decorator';
import { RbacManagerService } from '../../application/services/rbac-manager.service';

@Controller('rbac/data')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class RbacManagerController {
  constructor(private rbacManagerService: RbacManagerService) {}

  // 1. API UPLOAD (IMPORT)
  @Post('import')
  @Permissions('system:config') // Yêu cầu quyền cao nhất
  @UseInterceptors(FileInterceptor('file'))
  async importRbac(@UploadedFile() file: Express.Multer.File) {
    if (!file) {
      throw new BadRequestException('File is required');
    }

    // Check đuôi file hoặc mimetype cơ bản
    if (!file.originalname.endsWith('.csv')) {
      throw new BadRequestException('Only .csv files are allowed');
    }

    const content = file.buffer.toString('utf-8');
    const result = await this.rbacManagerService.importFromCsv(content);

    return {
      success: true,
      message: 'RBAC data imported successfully',
      stats: result
    };
  }

  // 2. API DOWNLOAD (EXPORT)
  @Get('export')
  @Permissions('system:config')
  async exportRbac(@Res({ passthrough: true }) res: Response) {
    const csvData = await this.rbacManagerService.exportToCsv();

    // Set header để trình duyệt hiểu đây là file tải về
    res.set({
      'Content-Type': 'text/csv',
      'Content-Disposition': 'attachment; filename="rbac_rules.csv"',
    });

    return new StreamableFile(Buffer.from(csvData));
  }
}
```

### Bước 4: Đăng ký vào RbacModule

Cập nhật file `src/modules/rbac/rbac.module.ts`:

```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { UserModule } from '../user/user.module';

// Controllers
import { RoleController } from './infrastructure/controllers/role.controller';
import { RbacManagerController } from './infrastructure/controllers/rbac-manager.controller'; // <--- MỚI

// Services
import { PermissionService } from './application/services/permission.service';
import { RoleService } from './application/services/role.service';
import { RbacManagerService } from './application/services/rbac-manager.service'; // <--- MỚI

// Guards
import { PermissionGuard } from './infrastructure/guards/permission.guard';

// Entities
import { Role } from './domain/entities/role.entity';
import { Permission } from './domain/entities/permission.entity';
import { UserRole } from './domain/entities/user-role.entity';

@Module({
  imports: [
    UserModule,
    TypeOrmModule.forFeature([Role, Permission, UserRole]),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        ttl: configService.get('RBAC_CACHE_TTL', 300),
        max: configService.get('RBAC_CACHE_MAX', 1000),
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [
    RoleController, 
    RbacManagerController // <--- Đăng ký Controller mới
  ],
  providers: [
    PermissionService, 
    RoleService, 
    PermissionGuard,
    RbacManagerService // <--- Đăng ký Service mới
  ],
  exports: [
    PermissionService, 
    PermissionGuard, 
    RoleService
  ],
})
export class RbacModule {}
```

### Bước 5: Hướng dẫn sử dụng

Sau khi code xong và chạy lại server (`docker-compose up -d --build`), bạn có thể thực hiện quy trình **Round-trip Engineering** như sau:

**1. Tải file cấu hình hiện tại về:**
*   **Method:** `GET`
*   **URL:** `http://localhost:3000/api/rbac/data/export`
*   **Auth:** Bearer Token của Super Admin.
*   **Kết quả:** Bạn sẽ nhận được file `rbac_rules.csv` chứa toàn bộ quyền hiện có trong DB.

**2. Chỉnh sửa file CSV trên máy:**
*   Mở bằng Excel hoặc Text Editor.
*   Thêm dòng mới (thêm quyền).
*   Sửa cột `description` hoặc `attributes`.
*   Lưu lại.

**3. Upload file đã sửa lên lại:**
*   **Method:** `POST`
*   **URL:** `http://localhost:3000/api/rbac/data/import`
*   **Body:** form-data, key `file` chọn file CSV vừa sửa.
*   **Auth:** Bearer Token của Super Admin.
*   **Kết quả:** Database sẽ được cập nhật các quyền mới/sửa đổi.

Đây là cách quản lý quyền cực kỳ chuyên nghiệp và dễ dàng cho việc vận hành hệ thống lớn.