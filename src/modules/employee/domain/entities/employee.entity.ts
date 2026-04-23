// src/modules/employee/domain/entities/employee.entity.ts
export interface EmployeeProps {
    id?: number;
    organizationId: number;
    userId?: number;
    employeeCode: string;
    fullName: string;
    dateOfBirth?: Date;
    phoneNumber?: string;
    avatarUrl?: string;
    locationId?: number;
    positionId?: number;
    managerId?: number;
    joinDate?: Date;
    createdAt?: Date;
    updatedAt?: Date;
}

export class Employee {
    public readonly id?: number;
    public organizationId: number;
    public userId?: number;
    public readonly employeeCode: string;
    public fullName: string;
    public dateOfBirth?: Date;
    public phoneNumber?: string;
    public avatarUrl?: string;
    public locationId?: number;
    public positionId?: number;
    public managerId?: number;
    public joinDate?: Date;
    public readonly createdAt?: Date;
    public updatedAt?: Date;

    constructor(props: EmployeeProps) {
        this.id = props.id;
        this.organizationId = props.organizationId;
        this.userId = props.userId;
        this.employeeCode = props.employeeCode;
        this.fullName = props.fullName;
        this.dateOfBirth = props.dateOfBirth;
        this.phoneNumber = props.phoneNumber;
        this.avatarUrl = props.avatarUrl;
        this.locationId = props.locationId;
        this.positionId = props.positionId;
        this.managerId = props.managerId;
        this.joinDate = props.joinDate;
        this.createdAt = props.createdAt;
        this.updatedAt = props.updatedAt;
    }

    // Logic nghiệp vụ: Liên kết tài khoản hệ thống
    linkUserAccount(userId: number) {
        if (this.userId) {
            throw new Error('Nhân viên này đã được liên kết với một tài khoản khác.');
        }
        this.userId = userId;
        this.updatedAt = new Date();
    }
}
