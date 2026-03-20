import os
import re

# ==========================================
# CÁC HÀM XỬ LÝ CHUỖI (STRING HELPERS)
# ==========================================
def to_kebab_case(name):
    # productCategory -> product-category
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1-\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1-\2', s1).lower()

def to_pascal_case(name):
    # product-category -> ProductCategory
    return ''.join(word.capitalize() for word in re.split('[-_ ]', to_kebab_case(name)))

def to_camel_case(name):
    # product-category -> productCategory
    pascal = to_pascal_case(name)
    return pascal[0].lower() + pascal[1:]

def to_snake_uppercase(name):
    # product-category -> PRODUCT_CATEGORY
    return to_kebab_case(name).replace('-', '_').upper()

# ==========================================
# HỆ THỐNG TEMPLATE (TYPESCRIPT)
# ==========================================
# Sử dụng ___VAR___ để thay thế an toàn, tránh xung đột dấu {} của TypeScript

TPL_ENTITY = """export class ___PascalName___ {
  constructor(
    public id: number | undefined,
    public name: string,
    public isActive: boolean = true,
    public createdAt?: Date,
    public updatedAt?: Date,
  ) {}

  // Thêm các hàm xử lý nghiệp vụ (Rich Domain Model) tại đây
  deactivate() {
    this.isActive = false;
    this.updatedAt = new Date();
  }

  toJSON() {
    return {
      id: this.id,
      name: this.name,
      isActive: this.isActive,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  }
}
"""

TPL_REPO_PORT = """import { ___PascalName___ } from '../entities/___kebabName___.entity';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export const I___PascalName___Repository = Symbol('I___PascalName___Repository');

export interface I___PascalName___Repository {
  save(entity: ___PascalName___, tx?: Transaction): Promise<___PascalName___>;
  findById(id: number, tx?: Transaction): Promise<___PascalName___ | null>;
  findAll(tx?: Transaction): Promise<___PascalName___[]>;
  delete(id: number, tx?: Transaction): Promise<void>;
}
"""

TPL_CONSTANTS = """export const ___SnakeUpperName____PERMISSIONS = {
    MANAGE: '___kebabName___:manage',
    READ: '___kebabName___:read',
    CREATE: '___kebabName___:create',
    UPDATE: '___kebabName___:update',
    DELETE: '___kebabName___:delete',
} as const;
"""

TPL_MAPPER = """import { ___PascalName___ } from '../../../domain/entities/___kebabName___.entity';
// TODO: Import schema tu @database/schema
// import { ___camelName___s } from '@database/schema';

export class ___PascalName___Mapper {
  static toDomain(raw: any | null): ___PascalName___ | null {
    if (!raw) return null;
    return new ___PascalName___(
      raw.id,
      raw.name,
      raw.isActive ?? true,
      raw.createdAt || undefined,
      raw.updatedAt || undefined,
    );
  }

  static toPersistence(domain: ___PascalName___): any {
    return {
      id: domain.id,
      name: domain.name,
      isActive: domain.isActive,
      createdAt: domain.createdAt || new Date(),
      updatedAt: domain.updatedAt || new Date(),
    };
  }
}
"""

TPL_DRIZZLE_REPO = """import { Injectable, Inject } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE } from '@database/drizzle.provider';
import * as schema from '@database/schema';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { I___PascalName___Repository } from '../../domain/repositories/___kebabName___.repository';
import { ___PascalName___ } from '../../domain/entities/___kebabName___.entity';
import { ___PascalName___Mapper } from './mappers/___kebabName___.mapper';

@Injectable()
export class Drizzle___PascalName___Repository 
  extends DrizzleBaseRepository 
  implements I___PascalName___Repository 
{
  constructor(@Inject(DRIZZLE) db: NodePgDatabase<typeof schema>) {
    super(db);
  }

  // TODO: Thay the 'schema.tableName' bang ten bang that cua ban
  async save(entity: ___PascalName___, tx?: Transaction): Promise<___PascalName___> {
    const db = this.getDb(tx);
    const data = ___PascalName___Mapper.toPersistence(entity);
    // Logic Insert hoac Update...
    return entity; 
  }

  async findById(id: number, tx?: Transaction): Promise<___PascalName___ | null> {
    const db = this.getDb(tx);
    // const result = await db.query.tableName.findFirst({ where: eq(schema.tableName.id, id) });
    // return ___PascalName___Mapper.toDomain(result);
    return null;
  }

  async findAll(tx?: Transaction): Promise<___PascalName___[]> {
    return [];
  }

  async delete(id: number, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    // await db.delete(schema.tableName).where(eq(schema.tableName.id, id));
  }
}
"""

TPL_SERVICE = """import { Injectable, Inject, NotFoundException } from '@nestjs/common';
import { I___PascalName___Repository } from '../../domain/repositories/___kebabName___.repository';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { ___PascalName___ } from '../../domain/entities/___kebabName___.entity';

@Injectable()
export class ___PascalName___Service {
  constructor(
    @Inject(I___PascalName___Repository) private readonly repo: I___PascalName___Repository,
    @Inject(ITransactionManager) private readonly txManager: ITransactionManager,
  ) {}

  async create(dto: any) {
    return this.txManager.runInTransaction(async (tx) => {
      const newEntity = new ___PascalName___(undefined, dto.name);
      return this.repo.save(newEntity, tx);
    });
  }

  async findById(id: number) {
    const entity = await this.repo.findById(id);
    if (!entity) throw new NotFoundException('___PascalName___ not found');
    return entity.toJSON();
  }
}
"""

TPL_CONTROLLER = """import { Controller, Get, Post, Body, Param, ParseIntPipe, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '@modules/rbac/infrastructure/guards/permission.guard';
import { Permissions } from '@modules/rbac/infrastructure/decorators/permission.decorator';
import { ___PascalName___Service } from '../../application/services/___kebabName___.service';
// import { ___SnakeUpperName____PERMISSIONS } from '../../domain/constants/___kebabName___.permissions';

@ApiTags('___PascalName___ Management')
@ApiBearerAuth()
@Controller('___kebabName___s')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class ___PascalName___Controller {
  constructor(private readonly service: ___PascalName___Service) {}

  @Post()
  @ApiOperation({ summary: 'Create a new ___PascalName___' })
  // @Permissions(___SnakeUpperName____PERMISSIONS.CREATE)
  async create(@Body() dto: any) {
    return this.service.create(dto);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get details' })
  // @Permissions(___SnakeUpperName____PERMISSIONS.READ)
  async findOne(@Param('id', ParseIntPipe) id: number) {
    return this.service.findById(id);
  }
}
"""

TPL_MODULE = """import { Module } from '@nestjs/common';
import { ___PascalName___Controller } from './infrastructure/controllers/___kebabName___.controller';
import { ___PascalName___Service } from './application/services/___kebabName___.service';
import { I___PascalName___Repository } from './domain/repositories/___kebabName___.repository';
import { Drizzle___PascalName___Repository } from './infrastructure/persistence/repositories/drizzle-___kebabName___.repository';
import { RbacModule } from '@modules/rbac/rbac.module';

@Module({
  imports: [RbacModule],
  controllers: [___PascalName___Controller],
  providers: [
    ___PascalName___Service,
    {
      provide: I___PascalName___Repository,
      useClass: Drizzle___PascalName___Repository,
    },
  ],
  exports: [___PascalName___Service, I___PascalName___Repository],
})
export class ___PascalName___Module {}
"""

# ==========================================
# LOGIC RENDER VÀ TẠO FILE
# ==========================================
def render(template, names):
    result = template
    for key, val in names.items():
        result = result.replace(f"___{key}___", val)
    return result

def create_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✅ Created: {path}")

def main():
    print("🚀 NESTJS CLEAN ARCHITECTURE - MODULE GENERATOR 🚀")
    print("-" * 50)
    
    raw_name = input("Nhập tên Module (VD: product, leave_request, salary_scale): ").strip()
    if not raw_name:
        print("❌ Tên module không hợp lệ!")
        return

    print("\nChọn cấp độ phức tạp:")
    print("1. Cơ bản (Entity, Repo, Service, Controller)")
    print("2. Nâng cao (Bao gồm Mapper và Domain Constants Permissions)")
    level = input("Nhập số (1 hoặc 2) [Mặc định: 2]: ").strip() or "2"

    names = {
        "kebabName": to_kebab_case(raw_name),
        "PascalName": to_pascal_case(raw_name),
        "camelName": to_camel_case(raw_name),
        "SnakeUpperName": to_snake_uppercase(raw_name)
    }

    base_dir = f"src/modules/{names['kebabName']}"

    if os.path.exists(base_dir):
        print(f"⚠️ Thư mục {base_dir} đã tồn tại! Hủy thao tác để tránh ghi đè.")
        return

    print(f"\n⏳ Đang khởi tạo module {names['PascalName']} ({base_dir})...")

    # 1. Tạo Domain Layer
    create_file(f"{base_dir}/domain/entities/{names['kebabName']}.entity.ts", render(TPL_ENTITY, names))
    create_file(f"{base_dir}/domain/repositories/{names['kebabName']}.repository.ts", render(TPL_REPO_PORT, names))
    
    if level == "2":
        create_file(f"{base_dir}/domain/constants/{names['kebabName']}.permissions.ts", render(TPL_CONSTANTS, names))

    # 2. Tạo Application Layer
    create_file(f"{base_dir}/application/services/{names['kebabName']}.service.ts", render(TPL_SERVICE, names))
    # Tạo folder dtos rỗng để dev tự định nghĩa
    os.makedirs(f"{base_dir}/application/dtos", exist_ok=True)

    # 3. Tạo Infrastructure Layer
    create_file(f"{base_dir}/infrastructure/controllers/{names['kebabName']}.controller.ts", render(TPL_CONTROLLER, names))
    create_file(f"{base_dir}/infrastructure/persistence/repositories/drizzle-{names['kebabName']}.repository.ts", render(TPL_DRIZZLE_REPO, names))
    
    if level == "2":
        create_file(f"{base_dir}/infrastructure/persistence/repositories/mappers/{names['kebabName']}.mapper.ts", render(TPL_MAPPER, names))

    # 4. Tạo Module File
    create_file(f"{base_dir}/{names['kebabName']}.module.ts", render(TPL_MODULE, names))

    print("-" * 50)
    print(f"🎉 TẠO MODULE {names['SnakeUpperName']} THÀNH CÔNG! 🎉")
    print("\n👉 CÁC BƯỚC TIẾP THEO BẠN CẦN LÀM:")
    print(f"1. Khai báo schema trong: src/database/schema/")
    print(f"2. Cập nhật lại TODO trong file Drizzle Repository và Mapper.")
    print(f"3. Thêm {names['PascalName']}Module vào mảng imports của src/bootstrap/app.module.ts")
    print(f"4. (Tùy chọn) Thêm Constant quyền vào src/modules/rbac/domain/constants/rbac.constants.ts\n")

if __name__ == "__main__":
    main()
