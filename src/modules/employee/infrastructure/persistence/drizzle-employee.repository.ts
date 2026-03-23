import { Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { IEmployeeRepository } from '../../domain/repositories/employee.repository';
import { employees } from '@database/schema/hrm/employees.schema'; // Import schema mới
import { like } from 'drizzle-orm';
import { orgUnits } from '@database/schema/hrm/org-structure.schema';
import { positions } from '@database/schema/hrm/org-structure.schema';

@Injectable()
export class DrizzleEmployeeRepository extends DrizzleBaseRepository implements IEmployeeRepository {

    async save(employeeData: any): Promise<any> {
        const db = this.getDb();

        // NẾU CÓ TRUYỀN ID -> THỰC HIỆN LỆNH UPDATE
        if (employeeData.id) {
            const [result] = await db.update(employees)
                .set({
                    ...employeeData,
                    updatedAt: new Date(), // Tự động cập nhật thời gian
                })
                .where(eq(employees.id, employeeData.id))
                .returning();
            return result;
        }

        // NẾU KHÔNG CÓ ID -> THỰC HIỆN LỆNH INSERT (THÊM MỚI)
        const [result] = await db.insert(employees)
            .values(employeeData)
            .returning();

        return result;
    }

    async findById(id: number): Promise<any> {
        const db = this.getDb();
        const result = await db.select().from(employees).where(eq(employees.id, id)).limit(1);
        return result[0] || null;
    }

    async findAll(options?: { orgPath?: string }): Promise<any[]> {
        const db = this.getDb();

        return await db.query.employees.findMany({
            where: (employees, { and, exists }) => {
                const filters = [];

                // Nếu có orgPath, chỉ lấy những nhân viên thuộc các phòng ban có path bắt đầu bằng orgPath này
                if (options?.orgPath) {
                    filters.push(
                        exists(
                            db.select()
                                .from(positions)
                                .innerJoin(orgUnits, eq(positions.orgUnitId, orgUnits.id))
                                .where(
                                    and(
                                        eq(positions.id, employees.positionId),
                                        like(orgUnits.path, `${options.orgPath}%`) // 🚀 Sức mạnh của Materialized Path
                                    )
                                )
                        )
                    );
                }
                return and(...filters);
            },
            with: {
                user: { columns: { username: true, email: true } },
                position: {
                    with: {
                        orgUnit: true,
                        grade: true
                    }
                },
                location: true
            }
        });
    }
}
