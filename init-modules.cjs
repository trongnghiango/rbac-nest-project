const fs = require('fs');
const path = require('path');

// =============================================================================
// CẤU HÌNH: NGUỒN (OLD MODULE) -> ĐÍCH (NEW MODULE)
// =============================================================================

const copyMap = [
  // 1. Interface Repository
  {
    src: 'src/modules/dental/domain/repositories/ortho.repository.ts',
    dest: 'src/modules/dental-treatment/domain/repositories/ortho.repository.ts'
  },
  // 2. Ports
  {
    src: 'src/modules/dental/domain/ports/dental-storage.port.ts',
    dest: 'src/modules/dental-treatment/domain/ports/dental-storage.port.ts'
  },
  {
    src: 'src/modules/dental/domain/ports/dental-worker.port.ts',
    dest: 'src/modules/dental-treatment/domain/ports/dental-worker.port.ts'
  },
  // 3. Types
  {
    src: 'src/modules/dental/domain/types/dental.types.ts',
    dest: 'src/modules/dental-treatment/domain/types/dental.types.ts'
  },
  // 4. DTOs (Chuyển từ infra cũ sang application mới cho chuẩn DDD)
  {
    src: 'src/modules/dental/infrastructure/dtos/upload-case.dto.ts',
    dest: 'src/modules/dental-treatment/application/dtos/upload-case.dto.ts' // Lưu ý folder đích
  },
  // 5. Workers & Provider
  {
    src: 'src/modules/dental/infrastructure/workers/piscina.provider.ts',
    dest: 'src/modules/dental-treatment/infrastructure/workers/piscina.provider.ts'
  },
  {
    src: 'src/modules/dental/infrastructure/workers/conversion.worker.ts', // Copy luôn worker file
    dest: 'src/modules/dental-treatment/infrastructure/workers/conversion.worker.ts'
  },
  // 6. Gateways
  {
    src: 'src/modules/dental/infrastructure/gateways/dental.gateway.ts',
    dest: 'src/modules/dental-treatment/infrastructure/gateways/dental.gateway.ts'
  },
  // 7. Utils (Parser) - Cần thiết cho worker/service
  {
    src: 'src/modules/dental/application/utils/movement.parser.ts',
    dest: 'src/modules/dental-treatment/application/utils/movement.parser.ts'
  },
  // 8. Adapters (Impl) - Cần để chạy Module
  {
    src: 'src/modules/dental/infrastructure/adapters/fs-dental-storage.adapter.ts',
    dest: 'src/modules/dental-treatment/infrastructure/adapters/fs-dental-storage.adapter.ts'
  },
  {
    src: 'src/modules/dental/infrastructure/adapters/piscina-worker.adapter.ts',
    dest: 'src/modules/dental-treatment/infrastructure/adapters/piscina-worker.adapter.ts'
  },
  // 9. Repository Implementation (Class DrizzleOrthoRepository)
  {
    src: 'src/modules/dental/infrastructure/persistence/drizzle-ortho.repository.ts',
    dest: 'src/modules/dental-treatment/infrastructure/persistence/repositories/drizzle-cases.repository.ts' // Đổi tên cho hợp
  }
];

// =============================================================================
// MAIN LOGIC
// =============================================================================

console.log('🚀 Đang di chuyển các file phụ trợ sang [dental-treatment]...\n');

copyMap.forEach(item => {
  const srcPath = path.join(__dirname, item.src);
  const destPath = path.join(__dirname, item.dest);

  if (fs.existsSync(srcPath)) {
    // Tạo thư mục đích nếu chưa có
    fs.mkdirSync(path.dirname(destPath), { recursive: true });

    // Copy file
    fs.copyFileSync(srcPath, destPath);
    console.log(`✅ Copied: ${path.basename(item.src)}`);
  } else {
    console.warn(`⚠️  Source missing: ${item.src}`);
  }
});

console.log('\n🎉 DONE! Các file đã được copy sang module mới.');