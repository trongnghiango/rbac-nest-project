// src/modules/accounting/infrastructure/adapters/puppeteer-pdf-generator.adapter.ts
import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { IDocumentGenerator } from '../../application/ports/document-generator.port';
import * as puppeteer from 'puppeteer';
import * as handlebars from 'handlebars';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class PuppeteerPdfGeneratorAdapter implements IDocumentGenerator {

    async generatePdfFromHtml(templateName: string, data: any): Promise<Buffer> {
        let browser;
        try {
            // 1. Đọc file Template HBS
            const templatePath = path.join(process.cwd(), 'src', 'modules', 'accounting', 'infrastructure', 'templates', `${templateName}.hbs`);

            if (!fs.existsSync(templatePath)) {
                throw new Error(`Template không tồn tại: ${templatePath}`);
            }

            const templateHtml = fs.readFileSync(templatePath, 'utf8');

            // 2. Biên dịch Handlebars (Nhồi data vào HTML)
            const template = handlebars.compile(templateHtml);
            const finalHtml = template(data);

            // 3. Khởi động Puppeteer (Trình duyệt ẩn)
            browser = await puppeteer.launch({
                headless: true,
                args: ['--no-sandbox', '--disable-setuid-sandbox'], // Cần thiết khi deploy lên Docker/Linux
            });
            const page = await browser.newPage();

            // 4. Load HTML vào trình duyệt
            await page.setContent(finalHtml, { waitUntil: 'networkidle0' });

            // 5. Xuất ra PDF chuẩn A4
            const pdfUint8Array = await page.pdf({
                format: 'A4',
                printBackground: true, // Quan trọng: Để in được màu nền của CSS (ví dụ màu xanh của Header)
                margin: {
                    top: '10mm',
                    right: '10mm',
                    bottom: '10mm',
                    left: '10mm',
                },
            });

            // 6. Chuyển Uint8Array về Buffer (Puppeteer bản mới trả về Uint8Array)
            return Buffer.from(pdfUint8Array);

        } catch (error) {
            console.error('Lỗi khi Generate PDF:', error);
            throw new InternalServerErrorException('Không thể tạo file PDF');
        } finally {
            // LUÔN LUÔN phải đóng browser để tránh rò rỉ RAM (Memory Leak)
            if (browser) {
                await browser.close();
            }
        }
    }
}
