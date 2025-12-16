#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🏛️ RESTORING PRO ARCHITECTURE (PURE TYPESCRIPT WORKER)..."

# 1. Viết lại Worker bằng TypeScript Chuẩn (Clean Code)
# Sử dụng import * as để đảm bảo type safety và tương thích
cat > src/modules/dental/infrastructure/workers/conversion.worker.ts << 'EOF'
import * as path from 'path';
import * as fs from 'fs-extra';
import { execFile } from 'child_process';
import * as util from 'util';
import * as crypto from 'crypto';

// Xử lý import cho các thư viện CommonJS legacy trong môi trường TS
// eslint-disable-next-line @typescript-eslint/no-var-requires
const AdmZip = require('adm-zip');

const execFilePromise = util.promisify(execFile);

// Định nghĩa Interface rõ ràng (DTO cho Worker)
export interface ConversionTask {
  objFilePath: string;
  outputDir: string;
  baseName: string;
  encryptionKey: string;
  config: {
    ratio: number;
    threshold: number;
    timeout: number;
  };
}

export interface WorkerResult {
  success: boolean;
  path: string;
}

// Hàm helper private
function findProjectRoot(startDir: string): string {
    let currentDir = path.resolve(startDir);
    // Giới hạn độ sâu tìm kiếm để tránh vòng lặp vô hạn
    for (let i = 0; i < 10; i++) {
        if (fs.existsSync(path.join(currentDir, "package.json"))) return currentDir;
        const parentDir = path.dirname(currentDir);
        if (parentDir === currentDir) break;
        currentDir = parentDir;
    }
    return startDir;
}

// Logic chính (Pure Async Function)
async function convertAndEncrypt(task: ConversionTask): Promise<WorkerResult> {
    const { objFilePath, outputDir, baseName, encryptionKey, config } = task;
    const tempDir = path.dirname(objFilePath);

    const initialGlb = path.join(tempDir, `${baseName}.initial.glb`);
    const simplifiedGlb = path.join(tempDir, `${baseName}.simplified.glb`);
    const optimizedGlb = path.join(tempDir, `${baseName}.optimized.glb`);
    const finalEncrypted = path.join(outputDir, `${baseName}.optimized.glb.enc`);

    const tempFiles = [initialGlb, simplifiedGlb, optimizedGlb];

    try {
        const projectRoot = findProjectRoot(process.cwd());
        const binPath = path.resolve(projectRoot, "node_modules", ".bin");
        const isWin = process.platform === "win32";

        const obj2gltf = path.join(binPath, isWin ? "obj2gltf.cmd" : "obj2gltf");
        const gltfTransform = path.join(binPath, isWin ? "gltf-transform.cmd" : "gltf-transform");
        const gltfPipeline = path.join(binPath, isWin ? "gltf-pipeline.cmd" : "gltf-pipeline");

        // Pipeline xử lý 3D
        await execFilePromise(obj2gltf, ["-i", objFilePath, "-o", initialGlb, "--binary"], { timeout: config.timeout });
        await execFilePromise(gltfTransform, ["simplify", initialGlb, simplifiedGlb, "--ratio", config.ratio.toString(), "--error", config.threshold.toString()], { timeout: config.timeout });
        await execFilePromise(gltfPipeline, ["-i", simplifiedGlb, "-o", optimizedGlb, "--draco.compressionLevel=10"], { timeout: config.timeout });

        // Mã hóa
        const fileBuffer = await fs.readFile(optimizedGlb);
        const key = Buffer.from(encryptionKey);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });

        const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
        const tag = cipher.getAuthTag();
        const finalBuffer = Buffer.concat([iv, encrypted, tag]);

        await fs.ensureDir(outputDir);
        await fs.writeFile(finalEncrypted, finalBuffer);

        return { success: true, path: finalEncrypted };

    } catch (error: any) {
        throw new Error(`Worker Processing Failed: ${error.message}`);
    } finally {
        // Dọn dẹp file tạm
        await Promise.all(tempFiles.map(f => fs.remove(f).catch(() => {})));
    }
}

// Export default chuẩn TypeScript
export default convertAndEncrypt;
EOF

# 2. Cấu hình Piscina Provider (Infrastructure Layer)
# Logic resolve path chính xác dựa trên cấu trúc build của NestJS
cat > src/modules/dental/infrastructure/workers/piscina.provider.ts << 'EOF'
import { Provider, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as path from 'path';
import * as fs from 'fs';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const Piscina = require('piscina');

export const PISCINA_POOL = 'PISCINA_POOL';

export const PiscinaProvider: Provider = {
  provide: PISCINA_POOL,
  useFactory: (config: ConfigService) => {
    const logger = new Logger('PiscinaProvider');
    const isProduction = process.env.NODE_ENV === 'production';

    // 1. Xác định gốc dự án (Root)
    const projectRoot = process.cwd();

    // 2. Xác định đường dẫn tương đối của worker file trong source
    const workerRelativePath = 'src/modules/dental/infrastructure/workers/conversion.worker';

    let workerPath: string;

    if (isProduction) {
        // PRODUCTION: Tìm trong folder 'dist'
        // NestJS build structure: dist/src/... hoặc dist/... (nếu config rootDir)
        // Check 1: dist/src/...
        const prodPath1 = path.join(projectRoot, 'dist', workerRelativePath + '.js');
        // Check 2: dist/... (loại bỏ 'src' prefix nếu flatten)
        const prodPath2 = path.join(projectRoot, 'dist', workerRelativePath.replace('src/', '') + '.js');

        if (fs.existsSync(prodPath1)) {
            workerPath = prodPath1;
        } else if (fs.existsSync(prodPath2)) {
            workerPath = prodPath2;
        } else {
             // Fallback khẩn cấp: Thử tìm ngay tại __dirname (nếu file provider và worker nằm cạnh nhau sau build)
             workerPath = path.join(__dirname, 'conversion.worker.js');
        }
    } else {
        // DEVELOPMENT: Tìm trong folder 'src' (ts-node)
        workerPath = path.join(projectRoot, workerRelativePath + '.ts');
    }

    if (!fs.existsSync(workerPath)) {
        logger.error(`CRITICAL: Worker file not found at calculated path: ${workerPath}`);
        // Thử list thư mục để debug nếu lỗi
        logger.error(`Dirname content: ${fs.readdirSync(__dirname)}`);
        throw new Error(`Worker file not found: ${workerPath}`);
    }

    logger.log(`🏊 Initializing Piscina with worker: ${workerPath}`);

    return new Piscina({
      filename: workerPath,
      minThreads: config.get('dental.minThreads'),
      maxThreads: config.get('dental.maxThreads'),
      // Chỉ dùng ts-node loader khi chạy file .ts
      execArgv: workerPath.endsWith('.ts') ? ['-r', 'ts-node/register'] : [],
    });
  },
  inject: [ConfigService],
};
EOF

success "✅ RESTORED PRO ARCHITECTURE! Worker is now pure TypeScript."
echo "👉 Restart server: npm run start:dev"
echo "👉 To test Production build: npm run build && node dist/bootstrap/main.js"