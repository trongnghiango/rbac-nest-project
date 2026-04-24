// src/modules/org-structure/infrastructure/persistence/mappers/org-structure.mapper.ts
import { OrgUnitEntity, PositionEntity } from "../../../domain/repositories/org-structure.repository";

export class OrgStructureMapper {
    static toDomainOrgUnit(raw: any): OrgUnitEntity {
        return {
            id: raw.id,
            organizationId: raw.organizationId,
            parentId: raw.parentId,
            code: raw.code,
            name: raw.name,
            type: raw.type,
            path: raw.path,
            isActive: raw.isActive,
            managerId: raw.managerId,
            createdAt: raw.createdAt,
            updatedAt: raw.updatedAt,
        };
    }

    static toDomainPosition(raw: any): PositionEntity {
        return {
            id: raw.id,
            orgUnitId: raw.orgUnitId,
            jobTitleId: raw.jobTitleId,
            gradeId: raw.gradeId,
            code: raw.code,
            name: raw.name,
            headcountLimit: raw.headcountLimit,
            isActive: raw.isActive,
            createdAt: raw.createdAt,
            updatedAt: raw.updatedAt,
        };
    }
}
