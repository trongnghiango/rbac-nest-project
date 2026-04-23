// src/modules/accounting/infrastructure/persistence/drizzle-finote.repository.ts
import { Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { IFinoteRepository } from '../../domain/repositories/finote.repository';
import * as schema from '@database/schema';

@Injectable()
export class DrizzleFinoteRepository extends DrizzleBaseRepository implements IFinoteRepository {
    async save(data: any): Promise<any> {
        const db = this.getDb();
        const [result] = await db
            .insert(schema.finotes)
            .values(data)
            .returning();
        return result;
    }

    async findById(id: number): Promise<any> {
        return this.getDb().query.finotes.findFirst({
            where: eq(schema.finotes.id, id),
        });
    }

    async addAttachment(data: any): Promise<void> {
        await this.getDb().insert(schema.finoteAttachments).values(data);
    }
}
