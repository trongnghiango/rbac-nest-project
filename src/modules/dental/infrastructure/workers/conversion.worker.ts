import * as path from 'path';
import * as fs from 'fs-extra';
import { spawn } from 'child_process';
import * as crypto from 'crypto';

// ==========================================
// 1. CONSTANTS & CONFIG
// ==========================================
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

// ==========================================
// 2. CUSTOM EXCEPTIONS
// ==========================================
export class WorkerBaseError extends Error {
  constructor(
    message: string,
    public readonly originalError?: unknown,
  ) {
    super(message);
    this.name = this.constructor.name;
    if (originalError instanceof Error) {
      this.stack += `\nCaused by: ${originalError.stack}`;
    }
  }
}
export class FileSystemError extends WorkerBaseError {}
export class ConversionProcessError extends WorkerBaseError {}
export class EncryptionError extends WorkerBaseError {}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error as any);
}

// ==========================================
// 3. INTERFACES
// ==========================================
export interface ConversionConfig {
  ratio: number;
  threshold: number;
  timeout: number;
}
export interface ConversionTask {
  objFilePath: string;
  outputDir: string;
  baseName: string;
  encryptionKey: string;
  config: ConversionConfig;
}
export interface WorkerResult {
  success: boolean;
  path: string;
}
interface Binaries {
  obj2gltf: string;
  gltfTransform: string;
  gltfPipeline: string;
}

// ==========================================
// 4. HELPER FUNCTIONS
// ==========================================

function findPackageRoot(packageName: string): string {
  const paths = require.resolve.paths(packageName) || [];
  paths.push(path.join(process.cwd(), 'node_modules'));
  for (const lookupPath of paths) {
    const candidatePath = path.join(lookupPath, packageName);
    if (fs.existsSync(path.join(candidatePath, 'package.json'))) {
      return candidatePath;
    }
  }
  throw new Error(`Package '${packageName}' not found in node_modules.`);
}

function resolvePackageBin(packageName: string): string {
  try {
    const packagePath = findPackageRoot(packageName);
    const pkgJson = fs.readJsonSync(path.join(packagePath, 'package.json'));
    let relativeBinPath = '';

    if (typeof pkgJson.bin === 'string') {
      relativeBinPath = pkgJson.bin;
    } else if (typeof pkgJson.bin === 'object') {
      const keys = Object.keys(pkgJson.bin);
      const cleanName = packageName.split('/').pop();
      if (cleanName && pkgJson.bin[cleanName]) {
        relativeBinPath = pkgJson.bin[cleanName];
      } else {
        relativeBinPath = pkgJson.bin[keys[0]];
      }
    }
    if (!relativeBinPath) throw new Error(`No binary found in ${packageName}`);
    return path.resolve(packagePath, relativeBinPath);
  } catch (error: any) {
    throw new Error(
      `Failed to resolve binary for ${packageName}: ${error.message}`,
    );
  }
}

function resolveBinaries(): Binaries {
  return {
    obj2gltf: resolvePackageBin('obj2gltf'),
    gltfTransform: resolvePackageBin('@gltf-transform/cli'),
    gltfPipeline: resolvePackageBin('gltf-pipeline'),
  };
}

async function runCommand(
  scriptPath: string,
  args: string[],
  timeout: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, ...args], {
      stdio: 'inherit', // Giữ nguyên log để debug
      timeout,
      env: process.env,
    });
    child.on('close', (code) => {
      if (code === 0) resolve();
      else
        reject(
          new ConversionProcessError(
            `Command ${path.basename(scriptPath)} failed with code ${code}`,
          ),
        );
    });
    child.on('error', (err) =>
      reject(new ConversionProcessError(err.message, err)),
    );
  });
}

/**
 * ✅ FIX QUAN TRỌNG: Mã hóa bằng Buffer (Sync logic in Async wrapper)
 * Thay vì dùng Stream dễ gây lỗi race condition (ghi chưa xong đã đóng file),
 * ta đọc toàn bộ file vào RAM -> Mã hóa -> Ghi xuống đĩa.
 * An toàn tuyệt đối cho file < 500MB.
 */
async function encryptFileBuffer(
  inputPath: string,
  outputPath: string,
  keyHex: string,
): Promise<void> {
  try {
    // 1. Kiểm tra file đầu vào có tồn tại và có dữ liệu không
    const stats = await fs.stat(inputPath);
    if (stats.size === 0) {
      throw new Error(
        `Input file for encryption is empty (0 bytes): ${inputPath}`,
      );
    }
    console.log(
      `🔒 Encrypting file: ${path.basename(inputPath)} (${stats.size} bytes)`,
    );

    // 2. Đọc file
    const fileData = await fs.readFile(inputPath);

    // 3. Chuẩn bị mã hóa
    const key = Buffer.from(keyHex);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    // 4. Mã hóa
    const encryptedContent = Buffer.concat([
      cipher.update(fileData),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // 5. Ghép: IV + EncryptedContent + AuthTag
    const finalBuffer = Buffer.concat([iv, encryptedContent, authTag]);

    // 6. Ghi file
    await fs.writeFile(outputPath, finalBuffer);
    console.log(`✅ Encrypted success: ${path.basename(outputPath)}`);
  } catch (error: unknown) {
    throw new EncryptionError(
      `Encryption failed: ${getErrorMessage(error)}`,
      error,
    );
  }
}

// ==========================================
// 5. MAIN LOGIC
// ==========================================

async function convertAndEncrypt(task: ConversionTask): Promise<WorkerResult> {
  const { objFilePath, outputDir, baseName, encryptionKey, config } = task;
  const tempDir = path.dirname(objFilePath);

  const paths = {
    initialGlb: path.join(tempDir, `${baseName}.initial.glb`),
    simplifiedGlb: path.join(tempDir, `${baseName}.simplified.glb`),
    optimizedGlb: path.join(tempDir, `${baseName}.optimized.glb`),
    finalEncrypted: path.join(outputDir, `${baseName}.optimized.glb.enc`),
  };

  const tempFiles = [paths.initialGlb, paths.simplifiedGlb, paths.optimizedGlb];

  try {
    console.log(`\n🚀 START WORKER: ${baseName}`);
    if (!fs.existsSync(objFilePath))
      throw new FileSystemError(`Input file missing: ${objFilePath}`);

    const bins = resolveBinaries();

    // Step 1: OBJ -> GLB
    await runCommand(
      bins.obj2gltf,
      ['-i', objFilePath, '-o', paths.initialGlb, '--binary'],
      config.timeout,
    );

    // Step 2: Simplify
    await runCommand(
      bins.gltfTransform,
      [
        'simplify',
        paths.initialGlb,
        paths.simplifiedGlb,
        '--ratio',
        config.ratio.toString(),
        '--error',
        config.threshold.toString(),
      ],
      config.timeout,
    );

    // Step 3: Optimize
    await runCommand(
      bins.gltfPipeline,
      [
        '-i',
        paths.simplifiedGlb,
        '-o',
        paths.optimizedGlb,
        '--draco.compressionLevel=7',
      ],
      config.timeout,
    );

    // Step 4: Encrypt (Dùng hàm mới)
    await fs.ensureDir(outputDir);

    // Kiểm tra kỹ file trước khi mã hóa
    if (!fs.existsSync(paths.optimizedGlb)) {
      throw new Error(
        `Optimization step succeeded but file not found: ${paths.optimizedGlb}`,
      );
    }

    await encryptFileBuffer(
      paths.optimizedGlb,
      paths.finalEncrypted,
      encryptionKey,
    );

    return { success: true, path: paths.finalEncrypted };
  } catch (error: unknown) {
    console.error(`❌ WORKER FAILED [${baseName}]:`, getErrorMessage(error));
    throw error;
  } finally {
    // Cleanup
    await Promise.all(tempFiles.map((f) => fs.remove(f).catch(() => {})));
  }
}

export default convertAndEncrypt;
