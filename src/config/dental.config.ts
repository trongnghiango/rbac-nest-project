// File: src/config/dental.config.ts
import { registerAs } from '@nestjs/config';
import * as path from 'path';
import * as fs from 'fs';

/**
 * 🛠️ RESOLVE BINARY THÔNG MINH (Dành cho Webpack + PNPM + Docker)
 * Thay vì mò mẫm tìm file .js bên trong ruột package (rất dễ gãy do pnpm symlink),
 * ta nhắm thẳng vào thư mục `.bin` do pnpm sinh ra lúc install.
 */
function getBinaryPath(binaryName: string): string {
  // 1. Gốc dự án (Trên Docker luôn là /app)
  const rootDir = process.cwd();

  // 2. Đường dẫn chuẩn tới thư mục Binaries của PNPM/NPM
  // VD: /app/node_modules/.bin/obj2gltf
  const localBinPath = path.join(rootDir, 'node_modules', '.bin', binaryName);

  if (fs.existsSync(localBinPath)) {
    return localBinPath;
  }

  // 3. Fallback tối thượng: Trả về đúng tên lệnh.
  // Lý do: Nếu trong Dockerfile bạn dùng `RUN npm install -g obj2gltf`, 
  // hệ điều hành (Linux) đã tự động map lệnh này vào biến toàn cục $PATH.
  // Khi gọi child_process.exec('obj2gltf'), Linux sẽ tự hiểu.
  return binaryName;
}

export default registerAs('dental', () => {
  // Lấy gốc dự án (process.cwd() thay vì __dirname để chống lỗi Webpack)
  const baseDir = process.cwd();

  return {
    // Upload & Storage Paths (An toàn tuyệt đối)
    uploadDir: process.env.DENTAL_UPLOAD_DIR || path.join(baseDir, 'uploads', 'dental', 'temp'),
    outputDir: process.env.DENTAL_OUTPUT_DIR || path.join(baseDir, 'uploads', 'dental', 'converted'),

    // Encryption
    encryptionKey: process.env.DENTAL_ENCRYPTION_KEY || 'qW9xZ2tL8mP4rN6vB3jF5hY7cT2kD9wE',

    // Conversion Settings
    simplificationRatio: 0.3,
    errorThreshold: 0.0005,
    timeout: 300000, // 5 mins

    // Worker Pool
    minThreads: parseInt(process.env.PISCINA_MIN_THREADS || '0', 10),
    maxThreads: parseInt(process.env.PISCINA_MAX_THREADS || '0', 10),

    // ✅ ĐƯỜNG DẪN BINARIES SIÊU CHUẨN: Ưu tiên ENV -> PNPM .bin -> Global Path
    binaries: {
      obj2gltf: process.env.BIN_OBJ2GLTF || getBinaryPath('obj2gltf'),

      gltfPipeline: process.env.BIN_GLTF_PIPELINE || getBinaryPath('gltf-pipeline'),

      // Lưu ý: Package name là @gltf-transform/cli, nhưng lệnh thực thi đăng ký trong package.json của nó tên là 'gltf-transform'
      gltfTransform: process.env.BIN_GLTF_TRANSFORM || getBinaryPath('gltf-transform'),
    },
  };
});
