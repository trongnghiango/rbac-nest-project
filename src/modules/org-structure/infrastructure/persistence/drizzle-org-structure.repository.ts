import { Injectable } from '@nestjs/common';
import { eq, and, sql, like } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { IOrgStructureRepository, OrgUnitEntity, PositionEntity } from '../../domain/repositories/org-structure.repository';
import { orgUnits, positions } from '@database/schema/hrm/org-structure.schema';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleOrgStructureRepository extends DrizzleBaseRepository implements IOrgStructureRepository {

    async createOrgUnit(data: Partial<OrgUnitEntity>, tx?: Transaction): Promise<OrgUnitEntity> {
        const db = this.getDb();
        const [result] = await db.insert(orgUnits).values(data as any).returning();
        return result as OrgUnitEntity;
    }

    async updateOrgUnit(id: number, data: Partial<OrgUnitEntity>, tx?: Transaction): Promise<OrgUnitEntity | null> {
        const db = this.getDb();
        const [result] = await db
            .update(orgUnits)
            .set({ ...data, updatedAt: new Date() })
            .where(eq(orgUnits.id, id))
            .returning();
        return result ? (result as OrgUnitEntity) : null;
    }

    // 🚀 MAGIC Ở ĐÂY: Update Path hàng loạt cho nhánh con bằng SQL REPLACE
    async updateDescendantsPath(oldPath: string, newPath: string, tx?: Transaction): Promise<void> {
        const db = this.getDb();
        await db.update(orgUnits)
            .set({
                // SQL: REPLACE(path, '/1/3/', '/1/5/3/')
                path: sql`REPLACE(${orgUnits.path}, ${oldPath}, ${newPath})`,
                updatedAt: new Date(),
            })
            // Chỉ tác động vào những node bắt đầu bằng oldPath (Cây con)
            .where(like(orgUnits.path, `${oldPath}%`));
    }

    async findByCode(code: string, tx?: Transaction): Promise<OrgUnitEntity | null> {
        const db = this.getDb();
        const result = await db.select().from(orgUnits).where(eq(orgUnits.code, code)).limit(1);
        return result[0] ? (result[0] as OrgUnitEntity) : null;
    }

    // 🚀 LẤY TOÀN BỘ CÂY CON CỰC NHANH VỚI MỆNH ĐỀ LIKE
    async findDescendantsByPath(path: string): Promise<OrgUnitEntity[]> {
        const db = this.getDb();
        return await db.select()
            .from(orgUnits)
            .where(like(orgUnits.path, `${path}%`));
    }

    async deleteOrgUnit(id: number, tx?: Transaction): Promise<boolean> {
        const db = this.getDb();
        try {
            // Sẽ báo lỗi nếu phòng này đang được làm parentId của phòng khác (do có FK)
            await db.delete(orgUnits).where(eq(orgUnits.id, id));
            return true;
        } catch (error) {
            return false; // Thường là lỗi vi phạm khóa ngoại
        }
    }

    async findById(id: number, tx?: Transaction): Promise<OrgUnitEntity | null> {
        const db = this.getDb();
        const result = await db.select().from(orgUnits).where(eq(orgUnits.id, id)).limit(1);
        return result[0] ? (result[0] as OrgUnitEntity) : null;
    }

    async findPositionById(id: number, tx?: Transaction): Promise<PositionEntity | null> {
        const db = this.getDb();
        const result = await db.select()
            .from(positions)
            .where(eq(positions.id, id))
            .limit(1);

        return result[0] ? (result[0] as PositionEntity) : null;
    }

    async findAllActiveUnits(): Promise<OrgUnitEntity[]> {
        const db = this.getDb();
        return await db.select().from(orgUnits).where(eq(orgUnits.isActive, true));

    }
}
