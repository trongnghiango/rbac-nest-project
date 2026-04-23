import { Contract, ContractStatus, ContractType } from '../../domain/entities/contract.entity';


export class ContractMapper {
    static toDomain(raw: any): Contract | null {
        if (!raw) return null;
        return new Contract({
            id: raw.id,
            organizationId: raw.organization_id,
            leadId: raw.lead_id,
            contractNumber: raw.contract_number,
            title: raw.title,
            contractType: raw.contract_type as ContractType,
            status: raw.status as ContractStatus,
            value: Number(raw.value),
            currency: raw.currency,
            signedAt: raw.signed_at,
        });
    }

    static toPersistence(domain: Contract) {
        return {
            id: domain.id,
            organization_id: domain.organizationId,
            lead_id: domain.leadId,
            contract_number: domain.contractNumber,
            title: domain.title,
            contract_type: domain.contractType,
            status: domain.status,
            value: domain.value.toString(),
            currency: domain.currency,
            signed_at: domain.signedAt,
        };
    }
}
