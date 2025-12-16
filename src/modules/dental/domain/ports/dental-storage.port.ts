export const IDentalStorage = Symbol('IDentalStorage');

export interface DentalFile {
  path: string;
  filename: string;
}

export interface IDentalStorage {
  ensureDirectories(): void;
  saveTempFile(file: Express.Multer.File): Promise<string>;
  extractZip(zipPath: string, extractPath: string): Promise<void>;
  findObjFilesRecursively(dir: string): Promise<string[]>;
  findEncFilesRecursively(dir: string): Promise<string[]>;
  removeFile(path: string): Promise<void>;
  removeDirectory(path: string): Promise<void>;
  getUploadDir(): string;
  getOutputDir(): string;
}
