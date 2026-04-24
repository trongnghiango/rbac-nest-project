// src/modules/employee/infrastructure/persistence/drizzle-employee.repository.ts
import { Injectable } from '@nestjs/common';
import { eq, and, like } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { IEmployeeRepository } from '../../domain/repositories/employee.repository';
import { employees } from '@database/schema/hrm/employees.schema';
import { orgUnits, positions } from '@database/schema/hrm/org-structure.schema';
import { EmployeeMapper } from './mappers/employee.mapper';
import { Employee } from '../../domain/entities/employee.entity';

@Injectable()
export class DrizzleEmployeeRepository extends DrizzleBaseRepository implements IEmployeeRepository {

    async save(employee: Employee): Promise<Employee> {
        const db = this.getDb();
        const data = EmployeeMapper.toPersistence(employee);

        let result;
        if (data.id) {
            const [updated] = await db.update(employees)
                .set({ ...data, updated_at: new Date() })
                .where(eq(employees.id, data.id))
                .returning();
            result = updated;
        } else {
            const { id, ...insertData } = data; // Loại bỏ id khi insert mới
            const [inserted] = await db.insert(employees)
                .values(insertData as any)
                .returning();
            result = inserted;
        }
        return EmployeeMapper.toDomain(result)!;
    }

    async findById(id: number): Promise<Employee | null> {
        const db = this.getDb();
        const result = await db.select().from(employees).where(eq(employees.id, id)).limit(1);
        return EmployeeMapper.toDomain(result[0]);
    }

    async findAll(options?: { orgPath?: string }): Promise<Employee[]> {
        const db = this.getDb();
        const results = await db.query.employees.findMany({
            where: (employees, { and, exists }) => {
                const filters = [];
                if (options?.orgPath) {
                    filters.push(
                        exists(
                            db.select()
                                .from(positions)
                                .innerJoin(orgUnits, eq(positions.orgUnitId, orgUnits.id))
                                .where(
                                    and(
                                        eq(positions.id, employees.positionId),
                                        like(orgUnits.path, `${options.orgPath}%`)
                                    )
                                )
                        )
                    );
                }
                return and(...filters);
            },
            with: {
                user: { columns: { username: true, email: true } },
                position: { with: { orgUnit: true, grade: true } },
                location: true
            }
        });

        return results.map(r => EmployeeMapper.toDomain(r)!);
    }
}