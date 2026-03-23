import { Injectable } from '@nestjs/common';
import { IFileParser } from '../../application/ports/file-parser.port';
import { parse } from 'csv-parse'; // 👉 DÙNG MODULE BẤT ĐỒNG BỘ
import { Readable } from 'stream'; // 👉 Core module của Node.js

@Injectable()
export class CsvParserAdapter implements IFileParser {
  async parseCsvAsync<T>(buffer: Buffer): Promise<T[]> {
    if (!buffer || buffer.length === 0) return [];

    const records: T[] = [];

    // 1. Biến Buffer (cục data trên RAM) thành một Stream (Luồng dữ liệu chảy từ từ)
    const stream = Readable.from(buffer);

    // 2. Cấu hình luồng Parse
    const parser = stream.pipe(
      parse({
        columns: true, // Lấy dòng đầu làm Headers
        skip_empty_lines: true,
        trim: true,
        bom: true, // ✅ QUAN TRỌNG: Thêm dòng này để loại bỏ ký tự ẩn \uFEFF của Windows
        relax_quotes: true, // ✅ Cho phép parse thoáng hơn nếu file có dấu ngoặc kép thừa
      })
    );

    try {
      // 3. Sử dụng Async Iterator (Tính năng cực mạnh của Node.js)
      // Vòng lặp này sẽ đọc từng chunk nhỏ. Nó sẽ NHƯỜNG Event Loop (non-blocking) 
      // cho các API khác chạy xen kẽ, giúp Server không bao giờ bị treo!
      for await (const record of parser) {
        records.push(record as T);
      }
      return records;
    } catch (error) {
      throw new Error(`Failed to parse CSV file: ${error.message}`);
    }
  }
}

