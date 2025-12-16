import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs-extra';
import * as path from 'path';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const AdmZip = require('adm-zip');
import { IDentalStorage } from '../../domain/ports/dental-storage.port';

@Injectable()
export class FileSystemDentalStorage implements IDentalStorage {
  private readonly uploadDir: string;
  private readonly outputDir: string;

  constructor(private readonly config: ConfigService) {
    const rawUploadDir = this.config.get('dental.uploadDir');
    const rawOutputDir = this.config.get('dental.outputDir');
    if (!rawUploadDir || !rawOutputDir)
      throw new Error('Dental Config Missing');

    this.uploadDir = path.resolve(rawUploadDir);
    this.outputDir = path.resolve(rawOutputDir);
  }

  ensureDirectories(): void {
    fs.ensureDirSync(this.uploadDir);
    fs.ensureDirSync(this.outputDir);
  }

  getUploadDir(): string {
    return this.uploadDir;
  }
  getOutputDir(): string {
    return this.outputDir;
  }

  async saveTempFile(file: Express.Multer.File): Promise<string> {
    // Multer đã lưu file rồi, hàm này chỉ để confirm hoặc move nếu cần
    return file.path;
  }

  async extractZip(zipPath: string, extractPath: string): Promise<void> {
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractPath, true);
  }

  async removeFile(path: string): Promise<void> {
    await fs.remove(path).catch(() => {});
  }

  async removeDirectory(path: string): Promise<void> {
    await fs.remove(path).catch(() => {});
  }

  async findObjFilesRecursively(dir: string): Promise<string[]> {
    return this.findFiles(dir, '.obj');
  }

  async findEncFilesRecursively(dir: string): Promise<string[]> {
    return this.findFiles(dir, '.enc');
  }

  private async findFiles(dir: string, ext: string): Promise<string[]> {
    let results: string[] = [];
    try {
      const list = await fs.readdir(dir);
      for (const file of list) {
        const fullPath = path.resolve(dir, file);
        const stat = await fs.stat(fullPath);
        if (stat && stat.isDirectory()) {
          results = results.concat(await this.findFiles(fullPath, ext));
        } else if (file.toLowerCase().endsWith(ext)) {
          results.push(fullPath);
        }
      }
    } catch (e) {
      /* ignore */
    }
    return results;
  }
}
