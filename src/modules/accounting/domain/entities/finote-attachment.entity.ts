// src/modules/accounting/domain/entities/finote-attachment.entity.ts
export interface FinoteAttachmentProps {
    id?: number;
    finoteId: number;
    fileName: string;
    googleDriveId?: string;
    webViewLink?: string;
    mimeType?: string;
    fileSize?: number;
    createdAt?: Date;
}

export class FinoteAttachment {
    public readonly id?: number;
    public readonly finoteId: number;
    public readonly fileName: string;
    public readonly googleDriveId?: string;
    public readonly webViewLink?: string;
    public readonly mimeType?: string;
    public readonly fileSize?: number;
    public readonly createdAt?: Date;

    constructor(props: FinoteAttachmentProps) {
        this.id = props.id;
        this.finoteId = props.finoteId;
        this.fileName = props.fileName;
        this.googleDriveId = props.googleDriveId;
        this.webViewLink = props.webViewLink;
        this.mimeType = props.mimeType;
        this.fileSize = props.fileSize;
        this.createdAt = props.createdAt || new Date();
    }
}
