import { Contract, ContractStatus, ContractType } from '../../domain/entities/contract.entity';


export class ContractMapper {
    static toDomain(raw: any): Contract | null {
        if (!raw) return null;
        return new Contract({
            id: raw.id,
            organizationId: raw.organizationId,
            leadId: raw.leadId,
            contractNumber: raw.contractNumber,
            title: raw.title,
            contractType: raw.type as ContractType,
            status: raw.status as ContractStatus,
            value: Number(raw.value),
            currency: raw.currency,
            signedAt: raw.signedAt,
        });
    }

    static toPersistence(domain: Contract) {
        return {
            id: domain.id,
            organizationId: domain.organizationId,
            leadId: domain.leadId,
            contractNumber: domain.contractNumber,
            title: domain.title,
            type: domain.contractType,
            status: domain.status,
            value: domain.value.toString(),
            currency: domain.currency,
            signedAt: domain.signedAt,
        };
    }
}
