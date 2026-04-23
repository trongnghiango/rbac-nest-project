// src/modules/accounting/infrastructure/adapters/local-file-storage.adapter.ts
import { Injectable } from '@nestjs/common';
import { IFileStorage } from '../../application/ports/file-storage.port';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class LocalFileStorageAdapter implements IFileStorage {
    async uploadBuffer(fileName: string, buffer: Buffer, mimeType: string): Promise<string> {
        const uploadDir = path.join(process.cwd(), 'uploads', 'finotes');

        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }

        const filePath = path.join(uploadDir, fileName);
        fs.writeFileSync(filePath, buffer);

        // Trả về URL dạng Public để FE có thể tải
        return `http://localhost:8080/public/finotes/${fileName}`;
    }
}
