export const IEmployeeRepository = Symbol('IEmployeeRepository');

export interface IEmployeeRepository {
    save(employeeData: any): Promise<any>;
    findById(id: number): Promise<any>;
    findAll(): Promise<any[]>;
}