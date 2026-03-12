export const IOrgStructureRepository = Symbol('IOrgStructureRepository');

export interface OrgUnitEntity {
    id: number;
    parentId: number | null;
    type: string;
    code: string;
    name: string;
    isActive: boolean | null;
}

export interface IOrgStructureRepository {
    createOrgUnit(data: Partial<OrgUnitEntity>): Promise<OrgUnitEntity>;
    updateOrgUnit(id: number, data: Partial<OrgUnitEntity>): Promise<OrgUnitEntity | null>;
    deleteOrgUnit(id: number): Promise<boolean>;
    findById(id: number): Promise<OrgUnitEntity | null>;

    // Lấy toàn bộ danh sách phòng ban (phục vụ việc vẽ cây)
    findAllActiveUnits(): Promise<OrgUnitEntity[]>;
}
