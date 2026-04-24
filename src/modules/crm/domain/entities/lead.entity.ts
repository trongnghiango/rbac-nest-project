import { LeadStage } from '../enums/lead-stage.enum';
export { LeadStage };

export interface LeadProps {
    id?: number;
    organizationId: number;
    contactId?: number;
    assignedToId?: number;
    createdById?: number;
    title: string;
    serviceNeed?: string;
    stage: LeadStage;
    source?: string;
    estimatedValue?: number;
    note?: string;
    expectedCloseDate?: Date;
    closedAt?: Date;
    lostReason?: string;
    createdAt?: Date;
    updatedAt?: Date;
}

export class Lead {
    // Sử dụng private để bảo vệ tính toàn vẹn của dữ liệu
    private _id?: number;
    private _organizationId: number;
    private _contactId?: number;
    private _assignedToId?: number;
    private _createdById?: number;
    private _title: string;
    private _serviceNeed?: string;
    private _stage: LeadStage;
    private _source?: string;
    private _estimatedValue?: number;
    private _note?: string;
    private _expectedCloseDate?: Date;
    private _closedAt?: Date;
    private _lostReason?: string;
    private _createdAt?: Date;
    private _updatedAt?: Date;

    // Áp dụng Destructuring Constructor để code cực kỳ sạch
    constructor(props: LeadProps) {
        const {
            id, organizationId, contactId, assignedToId, createdById,
            title, serviceNeed, stage, source, estimatedValue,
            note, expectedCloseDate, closedAt, lostReason,
            createdAt, updatedAt,
        } = props;

        this._id = id;
        this._organizationId = organizationId;
        this._contactId = contactId;
        this._assignedToId = assignedToId;
        this._createdById = createdById;
        this._title = title;
        this._stage = stage || LeadStage.NEW;
        this._serviceNeed = serviceNeed;
        this._source = source;
        this._estimatedValue = estimatedValue;
        this._note = note;
        this._expectedCloseDate = expectedCloseDate;
        this._closedAt = closedAt;
        this._lostReason = lostReason;
        this._createdAt = createdAt;
        this._updatedAt = updatedAt;
    }

    // --- GETTERS (Đọc dữ liệu) ---
    get id() { return this._id; }
    get organizationId() { return this._organizationId; }
    get contactId() { return this._contactId; }
    get assignedToId() { return this._assignedToId; }
    get title() { return this._title; }
    get stage() { return this._stage; }
    get estimatedValue() { return this._estimatedValue; }
    get note() { return this._note; }
    get expectedCloseDate() { return this._expectedCloseDate; }
    get closedAt() { return this._closedAt; } // Đã sửa từ closeAt -> closedAt cho đúng chuẩn
    get lostReason() { return this._lostReason; }
    get createdById() { return this._createdById }
    get serviceNeed() { return this._serviceNeed }
    get source() { return this._source }
    get createdAt() { return this._createdAt }
    get updatedAt() { return this._updatedAt }


    // --- HELPER METHODS (Kiểm tra trạng thái - Giúp Service cực sạch) ---
    isWon(): boolean { return this._stage === LeadStage.WON; }
    isLost(): boolean { return this._stage === LeadStage.LOST; }
    isNew(): boolean { return this._stage === LeadStage.NEW; }
    isConsulting(): boolean { return this._stage === LeadStage.CONSULTING; }

    // --- BUSINESS LOGIC (HÀNH VI CỦA THỰC THỂ) ---

    /**
     * Cập nhật thông tin cơ bản của Lead (Title, Note, ServiceNeed...)
     * Giúp tránh việc phải viết quá nhiều hàm setter riêng lẻ
     */
    updateInfo(data: Partial<LeadProps>): void {
        if (data.title) this._title = data.title;
        if (data.serviceNeed) this._serviceNeed = data.serviceNeed;
        if (data.note) this._note = data.note;
        if (data.source) this._source = data.source;
        if (data.expectedCloseDate) this._expectedCloseDate = data.expectedCloseDate;
        if (data.estimatedValue !== undefined) this._estimatedValue = data.estimatedValue;

        this._updatedAt = new Date();
    }

    /**
     * Chuyển đổi trạng thái Lead với các quy tắc nghiệp vụ
     */
    transitionTo(newStage: LeadStage): void {
        // Quy tắc 1: Không thể đổi trạng thái nếu đã chốt (WON)
        if (this.isWon()) {
            throw new Error('Không thể thay đổi trạng thái của một Lead đã chốt (WON).');
        }
        // Quy tắc 2: Không thể khôi phục Lead đã bị loại (LOST)
        if (this.isLost() && newStage !== LeadStage.LOST) {
            throw new Error('Lead đã bị loại (LOST) không thể khôi phục.');
        }

        this._stage = newStage;
        this._updatedAt = new Date();

        // Nếu chốt hoặc mất, ghi nhận thời điểm kết thúc
        if (newStage === LeadStage.WON || newStage === LeadStage.LOST) {
            this._closedAt = new Date();
        }
    }

    /**
     * Gán nhân viên phụ trách
     */
    assignTo(employeeId: number): void {
        this._assignedToId = employeeId;
        this._updatedAt = new Date();
    }

    /**
     * Đánh dấu Lead bị mất (Lost) kèm lý do
     */
    markAsLost(reason: string): void {
        this._stage = LeadStage.LOST;
        this._lostReason = reason;
        this._closedAt = new Date();
        this._updatedAt = new Date();
    }

    /**
     * Cập nhật giá trị ước tính (Có validate)
     */
    updateEstimate(value: number): void {
        if (value < 0) throw new Error('Giá trị ước tính không thể âm');
        this._estimatedValue = value;
        this._updatedAt = new Date();
    }

    closeAsWon() {
        if (this._stage === LeadStage.WON) {
            throw new Error('Lead này đã được chốt (WON) trước đó.');
        }

        if (!this._organizationId) {
            throw new Error('Lead phải được gắn với một Tổ chức/Khách hàng trước khi chốt.');
        }

        this._stage = LeadStage.WON;
        this._closedAt = new Date();
        this._updatedAt = new Date();
    }

}
