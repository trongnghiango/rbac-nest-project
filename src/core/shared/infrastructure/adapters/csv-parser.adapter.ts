import { Injectable } from '@nestjs/common';
import { IFileParser } from '../../application/ports/file-parser.port';
import { parse } from 'csv-parse/sync'; // Import module đồng bộ của csv-parse

@Injectable()
export class CsvParserAdapter implements IFileParser {
  parseCsv<T>(content: string): T[] {
    if (!content || content.trim() === '') return [];

    try {
      // Parse CSV chuyển thành mảng Objects tự động map theo Headers dòng đầu tiên
      const records = parse(content, {
        columns: true, // Lấy dòng đầu làm key (headers)
        skip_empty_lines: true, // Bỏ qua dòng trống
        trim: true, // Xóa khoảng trắng 2 đầu chữ
      });
      return records as T[];
    } catch (error) {
      throw new Error(`Failed to parse CSV file: ${error.message}`);
    }
  }
}
