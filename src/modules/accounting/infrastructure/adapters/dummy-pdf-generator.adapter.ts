// src/modules/accounting/infrastructure/adapters/dummy-pdf-generator.adapter.ts
import { Injectable } from '@nestjs/common';
import { IDocumentGenerator } from '../../application/ports/document-generator.port';

@Injectable()
export class DummyPdfGeneratorAdapter implements IDocumentGenerator {
    async generatePdfFromHtml(templateName: string, data: any): Promise<Buffer> {
        // [TODO CỦA BẠN]: Sau này import thư viện Puppeteer ở đây.
        // Ví dụ: const browser = await puppeteer.launch(); ...

        const fakeHtmlContent = `<html><body><h1>Hóa đơn ${data.invoiceCode}</h1></body></html>`;
        return Buffer.from(fakeHtmlContent, 'utf-8'); // Trả về file text giả làm PDF để code chạy được
    }
}
