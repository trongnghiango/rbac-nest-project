// src/modules/crm/domain/entities/organization.entity.ts
export enum OrganizationStatus {
    PROSPECT = 'PROSPECT',
    ACTIVE = 'ACTIVE',
    INACTIVE = 'INACTIVE',
}

export enum OrganizationType {
    INDIVIDUAL = 'INDIVIDUAL',
    ENTERPRISE = 'ENTERPRISE',
}

export interface OrganizationProps {
    id?: number;
    companyName: string;
    taxCode: string | null;
    type: OrganizationType;
    status: OrganizationStatus;
    isInternal: boolean;
    industry?: string;
    website?: string;
    address?: string;
    note?: string;
    createdAt?: Date;
    updatedAt?: Date;
}

export class Organization {
    private _id?: number;
    private _companyName: string;
    private _taxCode: string | null;
    private _type: OrganizationType;
    private _status: OrganizationStatus;
    private _isInternal: boolean;
    private _industry?: string;
    private _website?: string;
    private _address?: string;
    private _note?: string;
    private _createdAt?: Date;
    private _updatedAt?: Date;

    constructor(props: OrganizationProps) {
        this._id = props.id;
        this._companyName = props.companyName;
        this._taxCode = props.taxCode;
        this._type = props.type || OrganizationType.INDIVIDUAL;
        this._status = props.status || OrganizationStatus.PROSPECT;
        this._isInternal = props.isInternal ?? false;
        this._industry = props.industry;
        this._website = props.website;
        this._address = props.address;
        this._note = props.note;
        this._createdAt = props.createdAt || new Date();
        this._updatedAt = props.updatedAt || new Date();
    }

    // --- Getters ---
    get id() { return this._id; }
    get companyName() { return this._companyName; }
    get taxCode() { return this._taxCode; }
    get type() { return this._type; }
    get status() { return this._status; }
    get isInternal() { return this._isInternal; }
    get industry() { return this._industry; }
    get website() { return this._website; }
    get address() { return this._address; }
    get note() { return this._note; }
    get createdAt() { return this._createdAt; }
    get updatedAt() { return this._updatedAt; }

    // --- Business Logic (Rich Domain Model) ---

    /**
     * Kích hoạt tổ chức sang trạng thái ACTIVE
     */
    activate(): void {
        this._status = OrganizationStatus.ACTIVE;
        this.markModified();
    }

    /**
     * Tạm dừng hoạt động của tổ chức
     */
    deactivate(): void {
        this._status = OrganizationStatus.INACTIVE;
        this.markModified();
    }

    /**
     * Cập nhật thông tin pháp nhân (Vấn đề 2 trong Hiến pháp)
     * Tự động chuyển đổi sang ENTERPRISE nếu có mã số thuế
     */
    applyEnterpriseInfo(companyName?: string, taxCode?: string): void {
        if (companyName) {
            this._companyName = companyName.trim();
        }

        if (taxCode) {
            this._taxCode = taxCode.trim();
            // Logic nghiệp vụ đặc thù: Có MST thì auto là doanh nghiệp
            this._type = OrganizationType.ENTERPRISE;
        }

        this.markModified();
    }

    private markModified(): void {
        this._updatedAt = new Date();
    }

}

