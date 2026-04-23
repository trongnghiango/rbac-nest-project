import { Transaction } from "@core/shared/application/ports/transaction-manager.port";

export const IOrgStructureRepository = Symbol('IOrgStructureRepository');

export interface OrgUnitEntity {
    id: number;
    organizationId: number;
    parentId: number | null;
    path: string | null;
    type: string;
    code: string;
    name: string;
    isActive: boolean | null;

    createdAt?: Date;
    updatedAt?: Date;
}

// Bổ sung Type cho Vị trí định biên (Position)
export interface PositionEntity {
    id: number;
    code: string;
    name: string;
    orgUnitId: number;
    jobTitleId: number;
    gradeId: number;
    headcountLimit: number | null;
    isActive: boolean | null;
}

export interface IOrgStructureRepository {
    createOrgUnit(data: Partial<OrgUnitEntity>): Promise<OrgUnitEntity>;
    updateOrgUnit(id: number, data: Partial<OrgUnitEntity>): Promise<OrgUnitEntity | null>;
    deleteOrgUnit(id: number): Promise<boolean>;
    findById(id: number): Promise<OrgUnitEntity | null>;

    findByCode(code: string): Promise<OrgUnitEntity | null>;

    findPositionById(id: number): Promise<PositionEntity | null>;

    // 1. Cập nhật Path cho toàn bộ cây con khi Phòng ban cha bị di chuyển
    updateDescendantsPath(oldPath: string, newPath: string): Promise<void>;

    // 2. Lấy toàn bộ phòng ban con, cháu chắt (Flat list)
    findDescendantsByPath(path: string): Promise<OrgUnitEntity[]>;

    // Lấy toàn bộ danh sách phòng ban (phục vụ việc vẽ cây)
    findAllActiveUnits(): Promise<OrgUnitEntity[]>;
}
