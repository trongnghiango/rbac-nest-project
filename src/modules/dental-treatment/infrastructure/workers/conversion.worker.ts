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
// 3. INTERFACES (Imported or Re-defined)
// ==========================================
// Lưu ý: Trong Worker thread độc lập, tốt nhất là define lại interface hoặc import từ file shared không phụ thuộc NestJS
export interface ConversionBinaries {
  obj2gltf: string;
  gltfPipeline: string;
  gltfTransform: string;
}

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
  // ✅ Nhận binaries từ Main Thread
  binaries: ConversionBinaries;
}

export interface WorkerResult {
  success: boolean;
  path: string;
}

// ==========================================
// 4. HELPER FUNCTIONS
// ==========================================

async function runCommand(
  scriptPath: string,
  args: string[],
  timeout: number,
): Promise<void> {
  // ✅ Validate script existence before running
  if (!fs.existsSync(scriptPath)) {
    throw new Error(`Binary not found at path: ${scriptPath}`);
  }

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, ...args], {
      stdio: 'inherit',
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

async function encryptFileBuffer(
  inputPath: string,
  outputPath: string,
  keyHex: string,
): Promise<void> {
  try {
    const stats = await fs.stat(inputPath);
    if (stats.size === 0) {
      throw new Error(
        `Input file for encryption is empty (0 bytes): ${inputPath}`,
      );
    }
    console.log(
      `🔒 Encrypting file: ${path.basename(inputPath)} (${stats.size} bytes)`,
    );

    const fileData = await fs.readFile(inputPath);
    const key = Buffer.from(keyHex);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    const encryptedContent = Buffer.concat([
      cipher.update(fileData),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    const finalBuffer = Buffer.concat([iv, encryptedContent, authTag]);

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
  const { objFilePath, outputDir, baseName, encryptionKey, config, binaries } =
    task;
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

    // Step 1: OBJ -> GLB
    await runCommand(
      binaries.obj2gltf,
      ['-i', objFilePath, '-o', paths.initialGlb, '--binary'],
      config.timeout,
    );

    // Step 2: Simplify
    await runCommand(
      binaries.gltfTransform,
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
      binaries.gltfPipeline,
      [
        '-i',
        paths.simplifiedGlb,
        '-o',
        paths.optimizedGlb,
        '--draco.compressionLevel=7',
      ],
      config.timeout,
    );

    // Step 4: Encrypt
    await fs.ensureDir(outputDir);

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
    // Cleanup temp files
    await Promise.all(tempFiles.map((f) => fs.remove(f).catch(() => {})));
  }
}

export default convertAndEncrypt;
