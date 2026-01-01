import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs-extra';
import * as path from 'path';
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment,@typescript-eslint/no-require-imports
const AdmZip = require('adm-zip');
import { IDentalStorage } from '../../domain/ports/dental-storage.port';

@Injectable()
export class FileSystemDentalStorage implements IDentalStorage {
  private readonly _uploadDir: string;
  private readonly _outputDir: string;

  constructor(private readonly config: ConfigService) {
    const rawUploadDir = this.config.get('dental.uploadDir');
    const rawOutputDir = this.config.get('dental.outputDir');

    if (!rawUploadDir || !rawOutputDir) {
      throw new Error('Dental Config Missing (uploadDir or outputDir)');
    }

    this._uploadDir = path.resolve(rawUploadDir);
    this._outputDir = path.resolve(rawOutputDir);
  }

  // --- Getters ---
  get uploadDir(): string {
    return this._uploadDir;
  }

  get outputDir(): string {
    return this._outputDir;
  }

  // --- Path Utils ---
  joinPath(...segments: string[]): string {
    return path.join(...segments);
  }

  resolvePath(...segments: string[]): string {
    return path.resolve(...segments);
  }

  getBasename(p: string, ext?: string): string {
    return path.basename(p, ext);
  }

  getDirname(p: string): string {
    return path.dirname(p);
  }

  getRelativePath(from: string, to: string): string {
    const rel = path.relative(from, to);
    // Chuẩn hóa path separator thành '/' để dùng cho URL
    return rel.split(path.sep).join('/');
  }

  // --- File Ops ---
  ensureDirectories(): void {
    fs.ensureDirSync(this._uploadDir);
    fs.ensureDirSync(this._outputDir);
  }

  async readFile(filePath: string): Promise<Buffer> {
    return fs.readFile(filePath);
  }

  async exists(filePath: string): Promise<boolean> {
    return fs.pathExists(filePath);
  }

  async remove(filePath: string): Promise<void> {
    // fs-extra remove handles both file and dir, and doesn't throw if missing
    await fs.remove(filePath).catch(() => {});
  }

  async extractZip(zipPath: string, extractPath: string): Promise<void> {
    // AdmZip is sync mostly, wrapped in Promise for interface consistency
    return new Promise((resolve, reject) => {
      try {
        const zip = new AdmZip(zipPath);
        zip.extractAllTo(extractPath, true);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  }

  async findFilesRecursively(dir: string, ext: string): Promise<string[]> {
    let results: string[] = [];
    if (!(await fs.pathExists(dir))) return results;

    const list = await fs.readdir(dir);
    for (const file of list) {
      const fullPath = path.resolve(dir, file);
      const stat = await fs.stat(fullPath);
      if (stat.isDirectory()) {
        results = results.concat(
          await this.findFilesRecursively(fullPath, ext),
        );
      } else if (file.toLowerCase().endsWith(ext.toLowerCase())) {
        results.push(fullPath);
      }
    }
    return results;
  }
}
