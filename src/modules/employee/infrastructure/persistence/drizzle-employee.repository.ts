import { Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { IEmployeeRepository } from '../../domain/repositories/employee.repository';
import { employees } from '@database/schema/hrm/employees.schema'; // Import schema mới

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

    async findAll(): Promise<any[]> {
        const db = this.getDb();
        // Dùng Relational Query để lấy luôn thông tin User và Position (Nếu cần)
        return await db.query.employees.findMany({
            with: {
                user: { columns: { username: true, email: true } },
                position: true,
            }
        });
    }
}
