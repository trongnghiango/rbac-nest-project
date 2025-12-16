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
