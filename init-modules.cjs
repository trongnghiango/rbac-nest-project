const fs = require('fs');
const path = require('path');

// 1. Cấu hình danh sách Modules cần tạo
const modules = [
  'organization',      // Quản lý Clinic, Chi nhánh
  'patient',           // Quản lý Bệnh nhân
  'medical-staff',     // Quản lý Bác sĩ, Nhân viên
  'dental-treatment',  // Quản lý Ca điều trị, 3D (Module Dental cũ)
];

// 2. Cấu trúc thư mục chuẩn DDD (Level 2 - Standard)
const folderStructure = [
  'domain/entities',
  'domain/repositories', // Interfaces (Ports)
  'domain/services',     // Domain Logic
  'application/use-cases',
  'application/dtos',
  'infrastructure/controllers',
  'infrastructure/persistence/repositories', // Implementation (Adapters)
  'infrastructure/persistence/mappers',
  'infrastructure/persistence/schema',       // Database Schema tách nhỏ
];

const rootDir = path.join(__dirname, 'src', 'modules');

// Helper: Hàm tạo viết hoa chữ cái đầu (organization -> Organization)
const capitalize = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// Helper: Hàm chuyển kebab-case sang PascalCase (dental-treatment -> DentalTreatment)
const toPascalCase = (str) => {
  return str.split('-').map(capitalize).join('');
};

console.log(`🚀 Bắt đầu khởi tạo cấu trúc module tại: ${rootDir}\n`);

if (!fs.existsSync(rootDir)) {
  fs.mkdirSync(rootDir, { recursive: true });
}

modules.forEach((moduleName) => {
  const modulePath = path.join(rootDir, moduleName);
  const pascalName = toPascalCase(moduleName);

  console.log(`📦 Đang tạo module: [${moduleName}]...`);

  // 1. Tạo các thư mục con
  folderStructure.forEach((subFolder) => {
    const fullPath = path.join(modulePath, subFolder);
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
      // Tạo file .gitkeep để git track được thư mục rỗng
      fs.writeFileSync(path.join(fullPath, '.gitkeep'), '');
    }
  });

  // 2. Tạo file Module chính (VD: organization.module.ts)
  const moduleFilePath = path.join(modulePath, `${moduleName}.module.ts`);
  if (!fs.existsSync(moduleFilePath)) {
    const moduleContent = `import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [],
  providers: [],
  exports: [],
})
export class ${pascalName}Module {}
`;
    fs.writeFileSync(moduleFilePath, moduleContent);
    console.log(`   + Đã tạo file: ${moduleName}.module.ts`);
  } else {
    console.log(`   ! File module đã tồn tại, bỏ qua.`);
  }

  console.log(`✅ Hoàn tất module [${moduleName}]\n`);
});

console.log('🎉 KHỞI TẠO THÀNH CÔNG! Sẵn sàng để refactor.');
