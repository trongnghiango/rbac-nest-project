import * as path from 'path';
import * as fs from 'fs-extra';
import { execFile } from 'child_process';
import * as util from 'util';
import * as crypto from 'crypto';
import { pipeline } from 'stream/promises';

const execFilePromise = util.promisify(execFile);

// ==========================================
// 1. CONSTANTS & CONFIG
// ==========================================
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const MAX_SEARCH_DEPTH = 10;

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
  if (typeof error === 'string') return error;

  if (typeof error === 'object' && error !== null) {
    try {
      return JSON.stringify(error);
    } catch {
      // ignore
    }
  }
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

function findProjectRoot(startDir: string): string {
  let currentDir = path.resolve(startDir);
  for (let i = 0; i < MAX_SEARCH_DEPTH; i++) {
    if (fs.existsSync(path.join(currentDir, 'package.json'))) {
      return currentDir;
    }
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) break;
    currentDir = parentDir;
  }
  return startDir;
}

function resolveBinaries(): Binaries {
  const projectRoot = findProjectRoot(process.cwd());
  const binPath = path.resolve(projectRoot, 'node_modules', '.bin');
  const isWin = process.platform === 'win32';

  const getBinPath = (cmd: string) =>
    path.join(binPath, isWin ? `${cmd}.cmd` : cmd);

  const bins = {
    obj2gltf: getBinPath('obj2gltf'),
    gltfTransform: getBinPath('gltf-transform'),
    gltfPipeline: getBinPath('gltf-pipeline'),
  };

  if (!fs.existsSync(bins.obj2gltf))
    throw new FileSystemError(`Binary not found: ${bins.obj2gltf}`);

  return bins;
}

async function runCommand(
  bin: string,
  args: string[],
  timeout: number,
): Promise<void> {
  try {
    await execFilePromise(bin, args, { timeout });
  } catch (error: unknown) {
    const cmdName = path.basename(bin);
    throw new ConversionProcessError(
      `Command '${cmdName}' failed: ${getErrorMessage(error)}`,
      error,
    );
  }
}

async function encryptFileStream(
  inputPath: string,
  outputPath: string,
  keyHex: string,
): Promise<void> {
  try {
    const key = Buffer.from(keyHex);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    const readStream = fs.createReadStream(inputPath);
    const writeStream = fs.createWriteStream(outputPath);

    // FIX: Arrow function để khớp type
    if (!writeStream.write(iv)) {
      await new Promise<void>((resolve) =>
        writeStream.once('drain', () => resolve()),
      );
    }

    await pipeline(readStream, cipher, writeStream, { end: false });

    const authTag = cipher.getAuthTag();

    await new Promise<void>((resolve, reject) => {
      writeStream.write(authTag, (err) => {
        if (err) return reject(err);
        writeStream.end(() => resolve());
      });
    });
  } catch (error: unknown) {
    throw new EncryptionError(
      `Encryption failed for ${inputPath}: ${getErrorMessage(error)}`,
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
    if (!fs.existsSync(objFilePath)) {
      throw new FileSystemError(`Input file not found: ${objFilePath}`);
    }

    const bins = resolveBinaries();

    await runCommand(
      bins.obj2gltf,
      ['-i', objFilePath, '-o', paths.initialGlb, '--binary'],
      config.timeout,
    );

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

    await runCommand(
      bins.gltfPipeline,
      [
        '-i',
        paths.simplifiedGlb,
        '-o',
        paths.optimizedGlb,
        '--draco.compressionLevel=10',
      ],
      config.timeout,
    );

    await fs.ensureDir(outputDir);
    await encryptFileStream(
      paths.optimizedGlb,
      paths.finalEncrypted,
      encryptionKey,
    );

    return { success: true, path: paths.finalEncrypted };
  } catch (error: unknown) {
    if (error instanceof WorkerBaseError) {
      throw error;
    }
    throw new Error(`Unexpected Worker Error: ${getErrorMessage(error)}`);
  } finally {
    await Promise.all(
      tempFiles.map((f) =>
        fs.remove(f).catch(() => {
          /* ignore */
        }),
      ),
    );
  }
}

export default convertAndEncrypt;
