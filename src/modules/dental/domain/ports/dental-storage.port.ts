export const IDentalStorage = Symbol('IDentalStorage');

export interface IDentalStorage {
  // --- Path Management ---
  get uploadDir(): string;
  get outputDir(): string;

  /** Nối các đường dẫn (tương tự path.join) */
  joinPath(...segments: string[]): string;

  /** Giải quyết đường dẫn tuyệt đối (tương tự path.resolve) */
  resolvePath(...segments: string[]): string;

  /** Lấy tên file từ đường dẫn (tương tự path.basename) */
  getBasename(p: string, ext?: string): string;

  /** Lấy thư mục cha (tương tự path.dirname) */
  getDirname(p: string): string;

  /** Lấy đường dẫn tương đối (tương tự path.relative) - Luôn trả về forward slash '/' cho URL */
  getRelativePath(from: string, to: string): string;

  // --- File Operations ---
  ensureDirectories(): void;

  /** Đọc file vào Buffer */
  readFile(path: string): Promise<Buffer>;

  /** Kiểm tra file/folder tồn tại */
  exists(path: string): Promise<boolean>;

  /** Xóa file hoặc thư mục (recursive) */
  remove(path: string): Promise<void>;

  /** Giải nén file Zip */
  extractZip(zipPath: string, extractPath: string): Promise<void>;

  /** Tìm kiếm file theo đuôi mở rộng (đệ quy) */
  findFilesRecursively(dir: string, ext: string): Promise<string[]>;
}
