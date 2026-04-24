// src/modules/crm/domain/entities/contract.entity.ts
export enum ContractStatus {
    PENDING = 'PENDING',
    ACTIVE = 'ACTIVE',
    LIQUIDATED = 'LIQUIDATED',
}

export enum ContractType {
    RETAINER = 'RETAINER',
    ONE_OFF = 'ONE_OFF',
}

export interface ContractProps {
    id: number;
    organizationId: number;
    leadId: number | null;
    contractNumber: string;
    title: string;
    contractType: ContractType;
    status: ContractStatus;
    value: number;
    currency: string;
    signedAt?: Date;
}

export class Contract {
    public readonly id: number;
    public readonly organizationId: number;
    public readonly leadId: number | null;
    public readonly contractNumber: string;
    public readonly title: string;
    public readonly contractType: ContractType;
    public status: ContractStatus;
    public readonly value: number;
    public readonly currency: string;
    public readonly signedAt?: Date;

    constructor({
        id,
        organizationId,
        leadId,
        contractNumber,
        title,
        contractType,
        status,
        value,
        currency,
        signedAt,
    }: ContractProps) {
        this.id = id;
        this.organizationId = organizationId;
        this.leadId = leadId;
        this.contractNumber = contractNumber;
        this.title = title;
        this.contractType = contractType;
        this.status = status;
        this.value = value;
        this.currency = currency;
        this.signedAt = signedAt;
    }

    activate() { this.status = ContractStatus.ACTIVE; }

}
