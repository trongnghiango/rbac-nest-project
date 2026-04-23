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
    id: number;
    companyName: string;
    taxCode: string | null;
    type: OrganizationType;
    status: OrganizationStatus;
    isInternal: boolean;
    industry?: string;
    website?: string;
    address?: string;
    note?: string;
}

export class Organization {
    public readonly id: number;
    public companyName: string;
    public taxCode: string | null;
    public type: OrganizationType;
    public status: OrganizationStatus;
    public isInternal: boolean;
    public industry?: string;
    public website?: string;
    public address?: string;
    public note?: string;

    constructor({
        id,
        companyName,
        taxCode,
        type,
        status,
        isInternal,
        industry,
        website,
        address,
        note,
    }: OrganizationProps) {
        this.id = id;
        this.companyName = companyName;
        this.taxCode = taxCode;
        this.type = type;
        this.status = status;
        this.isInternal = isInternal;
        this.industry = industry;
        this.website = website;
        this.address = address;
        this.note = note;
    }

    activate() { this.status = OrganizationStatus.ACTIVE; }
    deactivate() { this.status = OrganizationStatus.INACTIVE; }

    toJSON() {
        return {
            id: this.id,
            companyName: this.companyName,
            taxCode: this.taxCode,
            type: this.type,
            status: this.status,
            isInternal: this.isInternal,
            industry: this.industry,
            website: this.website,
            address: this.address,
            note: this.note,
        };
    }
}
