import { Injectable } from '@nestjs/common';
import { eq, and, sql, like, inArray } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import {
  IOrgStructureRepository,
  OrgUnitEntity,
  PositionEntity,
} from '../../domain/repositories/org-structure.repository';
import {
  grades,
  jobTitles,
  locations,
  orgUnits,
  positions,
} from '@database/schema/hrm/org-structure.schema';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { OrgStructureMapper } from './mappers/org-structure.mapper';

@Injectable()
export class DrizzleOrgStructureRepository
  extends DrizzleBaseRepository
  implements IOrgStructureRepository
{
  async upsertLocations(data: { code: string; name: string }[]): Promise<void> {
    if (!data.length) return;
    await this.getDb()
      .insert(locations)
      .values(data)
      .onConflictDoNothing({ target: locations.code });
  }
  async findLocationsByCodes(
    codes: string[],
  ): Promise<{ id: number; code: string }[]> {
    if (!codes.length) return [];
    return this.getDb()
      .select({ id: locations.id, code: locations.code })
      .from(locations)
      .where(inArray(locations.code, codes));
  }
  async upsertGrades(
    data: { levelNumber: number; code: string; name: string }[],
  ): Promise<void> {
    if (!data.length) return;
    await this.getDb()
      .insert(grades)
      .values(data)
      .onConflictDoNothing({ target: grades.code });
  }

  async findGradesByLevels(
    levels: number[],
  ): Promise<{ id: number; levelNumber: number }[]> {
    if (!levels.length) return [];
    return this.getDb()
      .select({ id: grades.id, levelNumber: grades.levelNumber })
      .from(grades)
      .where(inArray(grades.levelNumber, levels));
  }
  async upsertJobTitles(names: string[]): Promise<void> {
    if (!names.length) return;
    const values = names.map((name) => ({ name }));
    await this.getDb()
      .insert(jobTitles)
      .values(values)
      .onConflictDoNothing({ target: jobTitles.name });
  }
  async findJobTitlesByNames(
    names: string[],
  ): Promise<{ id: number; name: string }[]> {
    if (!names.length) return [];
    return this.getDb()
      .select({ id: jobTitles.id, name: jobTitles.name })
      .from(jobTitles)
      .where(inArray(jobTitles.name, names));
  }
  async upsertOrgUnits(data: any[]): Promise<void> {
    if (!data.length) return;
    await this.getDb()
      .insert(orgUnits)
      .values(data)
      .onConflictDoNothing({ target: orgUnits.code });
  }

  async findOrgUnitsByCodes(
    codes: string[],
  ): Promise<{ id: number; code: string }[]> {
    if (!codes.length) return [];
    return this.getDb()
      .select({ id: orgUnits.id, code: orgUnits.code })
      .from(orgUnits)
      .where(inArray(orgUnits.code, codes));
  }

  async findPositionByCode(code: string): Promise<PositionEntity | null> {
    const result = await this.getDb()
      .select()
      .from(positions)
      .where(eq(positions.code, code))
      .limit(1);
    return result[0] ? OrgStructureMapper.toDomainPosition(result[0]) : null;
  }

  async createPosition(data: Partial<PositionEntity>): Promise<PositionEntity> {
    const [result] = await this.getDb()
      .insert(positions)
      .values(data as any)
      .returning();
    return OrgStructureMapper.toDomainPosition(result);
  }

  async createOrgUnit(data: Partial<OrgUnitEntity>): Promise<OrgUnitEntity> {
    const db = this.getDb();
    const [result] = await db
      .insert(orgUnits)
      .values(data as any)
      .returning();
    return OrgStructureMapper.toDomainOrgUnit(result);
  }

  async updateOrgUnit(
    id: number,
    data: Partial<OrgUnitEntity>,
  ): Promise<OrgUnitEntity | null> {
    const db = this.getDb();
    const [result] = await db
      .update(orgUnits)
      .set({ ...data, updatedAt: new Date() })
      .where(eq(orgUnits.id, id))
      .returning();
    return result ? OrgStructureMapper.toDomainOrgUnit(result) : null;
  }

  // 🚀 MAGIC Ở ĐÂY: Update Path hàng loạt cho nhánh con bằng SQL REPLACE
  async updateDescendantsPath(oldPath: string, newPath: string): Promise<void> {
    const db = this.getDb();
    await db
      .update(orgUnits)
      .set({
        // SQL: REPLACE(path, '/1/3/', '/1/5/3/')
        path: sql`REPLACE(${orgUnits.path}, ${oldPath}, ${newPath})`,
        updatedAt: new Date(),
      })
      // Chỉ tác động vào những node bắt đầu bằng oldPath (Cây con)
      .where(like(orgUnits.path, `${oldPath}%`));
  }

  async findByCode(code: string): Promise<OrgUnitEntity | null> {
    const db = this.getDb();
    const result = await db
      .select()
      .from(orgUnits)
      .where(eq(orgUnits.code, code))
      .limit(1);
    return result[0] ? OrgStructureMapper.toDomainOrgUnit(result[0]) : null;
  }

  // 🚀 LẤY TOÀN BỘ CÂY CON CỰC NHANH VỚI MỆNH ĐỀ LIKE
  async findDescendantsByPath(path: string): Promise<OrgUnitEntity[]> {
    const db = this.getDb();
    const results = await db
      .select()
      .from(orgUnits)
      .where(like(orgUnits.path, `${path}%`));
    return results.map(OrgStructureMapper.toDomainOrgUnit);
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
    const result = await db
      .select()
      .from(orgUnits)
      .where(eq(orgUnits.id, id))
      .limit(1);
    return result[0] ? OrgStructureMapper.toDomainOrgUnit(result[0]) : null;
  }

  async findPositionById(id: number): Promise<PositionEntity | null> {
    const db = this.getDb();
    const result = await db
      .select()
      .from(positions)
      .where(eq(positions.id, id))
      .limit(1);

    return result[0] ? OrgStructureMapper.toDomainPosition(result[0]) : null;
  }

  async findAllActiveUnits(): Promise<OrgUnitEntity[]> {
    const db = this.getDb();
    const results = await db.select().from(orgUnits).where(eq(orgUnits.isActive, true));
    return results.map(OrgStructureMapper.toDomainOrgUnit);
  }
}
