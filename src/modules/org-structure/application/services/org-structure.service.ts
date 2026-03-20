import { Injectable, Inject, NotFoundException, BadRequestException } from '@nestjs/common';
import { IOrgStructureRepository } from '../../domain/repositories/org-structure.repository';
import { CreateOrgUnitDto, UpdateOrgUnitDto } from '../dtos/org-unit.dto';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port'; // 👉 INJECT TRANSACTION

@Injectable()
export class OrgStructureService {
    constructor(
        @Inject(IOrgStructureRepository) private readonly repo: IOrgStructureRepository,
        @Inject(ITransactionManager) private readonly txManager: ITransactionManager,
    ) { }

    // 1. TẠO MỚI (Tự động tính toán Path)
    async createUnit(dto: CreateOrgUnitDto) {
        return this.txManager.runInTransaction(async (tx) => {
            let parentPath = '';

            if (dto.parentId) {
                const parent = await this.repo.findById(dto.parentId, tx);
                if (!parent) throw new NotFoundException('Phòng ban cha không tồn tại');
                parentPath = parent.path || '';
            }

            // Bước 1: Insert data vào DB để DB cấp ID tự động (Lúc này path = null)
            const newUnit = await this.repo.createOrgUnit(dto, tx);

            // Bước 2: Nối chuỗi tạo Path (VD: parent = /1/3/ -> path mới = /1/3/4/)
            const newPath = dto.parentId ? `${parentPath}${newUnit.id}/` : `/${newUnit.id}/`;

            // Bước 3: Update lại Path cho Unit vừa tạo
            return this.repo.updateOrgUnit(newUnit.id, { path: newPath }, tx);
        });
    }

    // 2. CẬP NHẬT (Xử lý thuật toán Di chuyển cành cây - Move Node)
    async updateUnit(id: number, dto: UpdateOrgUnitDto) {
        const unit = await this.repo.findById(id);
        if (!unit) throw new NotFoundException('Không tìm thấy phòng ban');

        return this.txManager.runInTransaction(async (tx) => {
            // NẾU CÓ SỰ THAY ĐỔI VỀ PHÒNG BAN CHA (Move Node)
            if (dto.parentId !== undefined && dto.parentId !== unit.parentId) {

                let newParentPath = '';
                if (dto.parentId) {
                    const newParent = await this.repo.findById(dto.parentId, tx);
                    if (!newParent) throw new NotFoundException('Phòng ban cha mới không tồn tại');

                    // 🚨 BẢO VỆ CHẶT CHẼ: Chống lỗi vòng lặp (Vác ông nội làm con của thằng cháu)
                    // Nếu path của cha mới bắt đầu bằng path của node hiện tại -> BÁO LỖI!
                    if (newParent.path?.startsWith(unit.path!)) {
                        throw new BadRequestException('Không thể di chuyển phòng ban này vào bên trong phòng ban con của chính nó!');
                    }
                    newParentPath = newParent.path || '';
                }

                const oldPath = unit.path!;
                const newPath = dto.parentId ? `${newParentPath}${unit.id}/` : `/${unit.id}/`;

                // Bước 1: Cập nhật thông tin node hiện tại
                await this.repo.updateOrgUnit(id, { ...dto, path: newPath }, tx);

                // Bước 2: Cập nhật Path cho TOÀN BỘ nhánh con bên dưới (Descendants)
                await this.repo.updateDescendantsPath(oldPath, newPath, tx);

            } else {
                // Cập nhật bình thường (Đổi tên, trạng thái) không ảnh hưởng tới cây
                await this.repo.updateOrgUnit(id, dto, tx);
            }

            return this.repo.findById(id, tx);
        });
    }

    // 3. XÓA (Check an toàn bằng Path)
    async deleteUnit(id: number) {
        const unit = await this.repo.findById(id);
        if (!unit) throw new NotFoundException('Không tìm thấy phòng ban');

        // Check xem có phòng ban con nào mang path của node này không
        const descendants = await this.repo.findDescendantsByPath(unit.path!);
        if (descendants.length > 1) { // Lớn hơn 1 vì nó đếm cả chính nó
            throw new BadRequestException('Không thể xóa. Có phòng ban con đang trực thuộc đơn vị này.');
        }

        await this.repo.deleteOrgUnit(id);
        return { message: 'Xóa thành công' };
    }

    // 4. BIỂU DIỄN SỨC MẠNH CỦA PATH (API Lấy phòng ban + toàn bộ cấp dưới)
    async getDepartmentWithAllDescendants(id: number) {
        const unit = await this.repo.findById(id);
        if (!unit) throw new NotFoundException('Không tìm thấy phòng ban');

        // Chỉ bằng 1 câu LIKE, ta lấy được toàn bộ Sơ đồ tổ chức từ Node này trở xuống
        const flatList = await this.repo.findDescendantsByPath(unit.path!);
        return flatList;
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

    // HÀM MIGRATION: Cập nhật Path cho dữ liệu cũ - cái này có thể sẽ không dùng nếu là mới
    async migrateAllNullPaths() {
        // 1. Lấy toàn bộ phòng ban lên RAM
        const allUnits = await this.repo.findAllActiveUnits(); // Hoặc viết hàm lấy cả unit ko active

        // 2. Chuyển thành Dictionary (Map) để tra cứu cực nhanh O(1)
        const unitMap = new Map(allUnits.map(u => [u.id, u]));
        const calculatedPaths = new Map<number, string>(); // Lưu path đã tính

        // 3. Hàm đệ quy tính Path
        const calculatePath = (id: number): string => {
            // Nếu đã tính rồi thì lấy ra dùng luôn (Tránh tính lại)
            if (calculatedPaths.has(id)) return calculatedPaths.get(id)!;

            const unit = unitMap.get(id);
            if (!unit) return ''; // Trường hợp data rác, parentId trỏ đi đâu không biết

            // Nếu là Root Node
            if (!unit.parentId) {
                const newPath = `/${unit.id}/`;
                calculatedPaths.set(id, newPath);
                return newPath;
            }

            // Nếu là Child Node -> Gọi đệ quy lấy Path của Cha, rồi nối ID của mình vào
            const parentPath = calculatePath(unit.parentId);
            const newPath = `${parentPath}${unit.id}/`;

            calculatedPaths.set(id, newPath);
            return newPath;
        };

        // 4. Bắt đầu tính toán cho tất cả
        for (const unit of allUnits) {
            if (!unit.path) { // Chỉ tính những thằng đang bị null
                calculatePath(unit.id);
            }
        }

        // 5. Cập nhật hàng loạt xuống DB (Dùng Transaction để an toàn)
        await this.txManager.runInTransaction(async (tx) => {
            const promises: Promise<any>[] = [];

            for (const [id, newPath] of calculatedPaths.entries()) {
                promises.push(this.repo.updateOrgUnit(id, { path: newPath }, tx));
            }

            await Promise.all(promises);
        });

        return {
            success: true,
            message: `Đã Migrate thành công ${calculatedPaths.size} phòng ban!`,
            data: Object.fromEntries(calculatedPaths) // Trả về xem chơi cho vui
        };
    }
}
