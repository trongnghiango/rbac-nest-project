// src/modules/accounting/application/ports/document-generator.port.ts
export const IDocumentGenerator = Symbol('IDocumentGenerator');

export interface IDocumentGenerator {
    /**
     * Truyền vào template HTML và Data, trả về Buffer của file PDF
     */
    generatePdfFromHtml(templateName: string, data: any): Promise<Buffer>;
}
