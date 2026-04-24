// src/modules/employee/domain/repositories/employee.repository.ts
import { Employee } from '../entities/employee.entity';

export const IEmployeeRepository = Symbol('IEmployeeRepository');

export interface IEmployeeRepository {
    save(employee: Employee): Promise<Employee>;
    findById(id: number): Promise<Employee | null>;
    findAll(options?: { orgPath?: string }): Promise<Employee[]>;
}
