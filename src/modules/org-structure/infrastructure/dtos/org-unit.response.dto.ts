export class OrgUnitResponseDto {
    id: number;
    organizationId: number;
    parentId: number | null;
    type: string;
    code: string;
    name: string;
    isActive: boolean;

    static fromDomain(entity: any): OrgUnitResponseDto {
        return {
            id: entity.id,
            organizationId: entity.organizationId,
            parentId: entity.parentId,
            type: entity.type,
            code: entity.code,
            name: entity.name,
            isActive: entity.isActive,
        };
    }

    static fromTree(treeNodes: any[]): any[] {
        return treeNodes.map(node => ({
            ...this.fromDomain(node),
            children: node.children ? this.fromTree(node.children) : [],
        }));
    }
}
