export const IFileParser = Symbol('IFileParser');

export interface IFileParser {
  // Thay đổi: Nhận vào raw Buffer và trả về Promise để không block Event Loop
  parseCsvAsync<T>(buffer: Buffer): Promise<T[]>;
}
