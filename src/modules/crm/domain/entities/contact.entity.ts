// src/modules/crm/domain/entities/contact.entity.ts

export interface ContactProps {
    id?: number;
    organizationId: number;
    fullName: string;
    phone?: string;
    email?: string;
    position?: string;
    isMain: boolean;
    createdAt?: Date;
    updatedAt?: Date;
}

export class Contact {
    public readonly id?: number;
    public readonly organizationId: number;
    public fullName: string;
    public readonly phone?: string;
    public readonly email?: string;
    public position?: string;
    public isMain: boolean;
    public readonly createdAt?: Date;
    public updatedAt?: Date;

    constructor(props: ContactProps) {
        this.id = props.id;
        this.organizationId = props.organizationId;
        this.fullName = props.fullName;
        this.phone = props.phone;
        this.email = props.email;
        this.position = props.position;
        this.isMain = props.isMain ?? false;
        this.createdAt = props.createdAt;
        this.updatedAt = props.updatedAt;
    }
}
