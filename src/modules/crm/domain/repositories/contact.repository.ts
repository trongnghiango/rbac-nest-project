// src/modules/crm/domain/repositories/contact.repository.ts
import { Contact } from '@modules/crm/domain/entities/contact.entity';

export const IContactRepository = Symbol('IContactRepository');

export interface IContactRepository {
    findById(id: number): Promise<Contact | null>;
    findByPhone(phone: string): Promise<Contact | null>;
    save(contact: Contact): Promise<Contact>;
}
