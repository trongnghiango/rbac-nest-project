import { Injectable, Inject, NotFoundException, BadRequestException } from '@nestjs/common';
import { IOrgStructureRepository } from '../../domain/repositories/org-structure.repository';
import { CreateOrgUnitDto, UpdateOrgUnitDto } from '../dtos/org-unit.dto';

@Injectable()
export class OrgStructureService {
    constructor(
        @Inject(IOrgStructureRepository) private readonly repo: IOrgStructureRepository,
    ) { }

    async createUnit(dto: CreateOrgUnitDto) {
        if (dto.parentId) {
            const parent = await this.repo.findById(dto.parentId);
            if (!parent) throw new NotFoundException('Phòng ban cha không tồn tại');
        }
        return this.repo.createOrgUnit(dto);
    }

    async updateUnit(id: number, dto: UpdateOrgUnitDto) {
        const unit = await this.repo.updateOrgUnit(id, dto);
        if (!unit) throw new NotFoundException('Không tìm thấy phòng ban');
        return unit;
    }

    async deleteUnit(id: number) {
        const success = await this.repo.deleteOrgUnit(id);
        if (!success) throw new BadRequestException('Không thể xóa. Vui lòng kiểm tra xem phòng ban này có chứa phòng ban con không.');
        return { message: 'Xóa thành công' };
    }

    // 🚀 THUẬT TOÁN VẼ CÂY SƠ ĐỒ TỔ CHỨC SIÊU TỐC
    async getOrganizationTree() {
        // 1. Lấy toàn bộ data dạng phẳng (Flat List) từ DB -> Cực nhanh
        const allUnits = await this.repo.findAllActiveUnits();

        // 2. Chuyển đổi thành cấu trúc Cây (Tree) trên RAM (O(N) Complexity)
        const tree: any[] = [];
        const lookup = new Map<number, any>();

        // Khởi tạo lookup map
        allUnits.forEach(unit => {
            lookup.set(unit.id, { ...unit, children: [] });
        });

        // Ráp nối cha con
        allUnits.forEach(unit => {
            const node = lookup.get(unit.id);
            if (unit.parentId === null) {
                tree.push(node); // Là node gốc (Company)
            } else {
                const parentNode = lookup.get(unit.parentId);
                if (parentNode) {
                    parentNode.children.push(node);
                }
            }
        });

        return tree;
    }
}
