import { registerAs } from '@nestjs/config';
import * as path from 'path';

// Helper để resolve đường dẫn an toàn, fallback nếu không tìm thấy
function safeResolve(packageName: string, subPath: string): string {
  try {
    // 1. Ưu tiên tìm trong project hiện tại
    return require.resolve(`${packageName}/${subPath}`);
  } catch (e) {
    // 2. Fallback đơn giản (cho trường hợp Docker global install)
    return path.resolve('node_modules', packageName, subPath);
  }
}

export default registerAs('dental', () => ({
  // Upload & Storage Paths
  uploadDir: process.env.DENTAL_UPLOAD_DIR || 'uploads/dental/temp',
  outputDir: process.env.DENTAL_OUTPUT_DIR || 'uploads/dental/converted',

  // Encryption
  encryptionKey:
    process.env.DENTAL_ENCRYPTION_KEY || 'qW9xZ2tL8mP4rN6vB3jF5hY7cT2kD9wE',

  // Conversion Settings
  simplificationRatio: 0.3,
  errorThreshold: 0.0005,
  timeout: 300000, // 5 mins

  // Worker Pool
  minThreads: parseInt(process.env.PISCINA_MIN_THREADS || '0', 10),
  maxThreads: parseInt(process.env.PISCINA_MAX_THREADS || '0', 10),

  // ✅ NEW: Định nghĩa đường dẫn Binaries cụ thể (Ưu tiên ENV -> Node Resolve)
  binaries: {
    obj2gltf:
      process.env.BIN_OBJ2GLTF || safeResolve('obj2gltf', 'bin/obj2gltf.js'),
    gltfPipeline:
      process.env.BIN_GLTF_PIPELINE ||
      safeResolve('gltf-pipeline', 'bin/gltf-pipeline.js'),
    gltfTransform:
      process.env.BIN_GLTF_TRANSFORM ||
      safeResolve('@gltf-transform/cli', 'bin/cli.js'),
  },
}));
