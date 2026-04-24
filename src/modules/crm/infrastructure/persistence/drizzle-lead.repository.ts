import { Injectable, Inject } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { ILeadRepository } from '../../domain/repositories/lead.repository';
import { Lead, LeadStage } from '../../domain/entities/lead.entity';
import { LeadMapper } from '../mappers/lead.mapper';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';

@Injectable()
export class DrizzleLeadRepository extends DrizzleBaseRepository implements ILeadRepository {
    constructor(@Inject(DRIZZLE) db: NodePgDatabase<typeof schema>) {
        super(db);
    }

    async findById(id: number): Promise<Lead | null> {
        const row = await this.getDb().query.leads.findFirst({ where: eq(schema.leads.id, id) });
        return LeadMapper.toDomain(row);
    }

    async save(lead: Lead): Promise<Lead> {
        const data = LeadMapper.toPersistence(lead);
        const [result] = await this.getDb().insert(schema.leads).values(data as any).onConflictDoUpdate({
            target: schema.leads.id,
            set: data,
        }).returning();
        return LeadMapper.toDomain(result);
    }

    async updateStage(id: number, stage: LeadStage): Promise<void> {
        await this.getDb().update(schema.leads)
            .set({ stage: stage as any, updated_at: new Date() })
            .where(eq(schema.leads.id, id));
    }
}
