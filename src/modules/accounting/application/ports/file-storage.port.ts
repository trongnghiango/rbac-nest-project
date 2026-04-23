// src/modules/accounting/application/ports/file-storage.port.ts
export const IFileStorage = Symbol('IFileStorage');

export interface IFileStorage {
    /**
     * Lưu buffer thành file và trả về URL để truy cập
     */
    uploadBuffer(fileName: string, buffer: Buffer, mimeType: string): Promise<string>;
}
