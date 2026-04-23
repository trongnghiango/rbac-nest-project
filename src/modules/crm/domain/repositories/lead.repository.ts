// src/modules/crm/domain/repositories/lead.repository.ts
import { Lead } from '../entities/lead.entity';

export const ILeadRepository = Symbol('ILeadRepository');

export interface ILeadRepository {
    findById(id: number): Promise<Lead | null>;
    save(lead: Lead): Promise<Lead>;
    updateStage(id: number, stage: string): Promise<void>;
}

