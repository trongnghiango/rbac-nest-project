import { Injectable } from '@nestjs/common';
import { eq, and } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { IOrgStructureRepository, OrgUnitEntity, PositionEntity } from '../../domain/repositories/org-structure.repository';
import { orgUnits, positions } from '@database/schema/hrm/org-structure.schema';

@Injectable()
export class DrizzleOrgStructureRepository extends DrizzleBaseRepository implements IOrgStructureRepository {

    async createOrgUnit(data: Partial<OrgUnitEntity>): Promise<OrgUnitEntity> {
        const db = this.getDb();
        const [result] = await db.insert(orgUnits).values(data as any).returning();
        return result as OrgUnitEntity;
    }

    async updateOrgUnit(id: number, data: Partial<OrgUnitEntity>): Promise<OrgUnitEntity | null> {
        const db = this.getDb();
        const [result] = await db
            .update(orgUnits)
            .set({ ...data, updatedAt: new Date() })
            .where(eq(orgUnits.id, id))
            .returning();
        return result ? (result as OrgUnitEntity) : null;
    }

    async deleteOrgUnit(id: number): Promise<boolean> {
        const db = this.getDb();
        try {
            // Sẽ báo lỗi nếu phòng này đang được làm parentId của phòng khác (do có FK)
            await db.delete(orgUnits).where(eq(orgUnits.id, id));
            return true;
        } catch (error) {
            return false; // Thường là lỗi vi phạm khóa ngoại
        }
    }

    async findById(id: number): Promise<OrgUnitEntity | null> {
        const db = this.getDb();
        const result = await db.select().from(orgUnits).where(eq(orgUnits.id, id)).limit(1);
        return result[0] ? (result[0] as OrgUnitEntity) : null;
    }

    async findPositionById(id: number): Promise<PositionEntity | null> {
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
