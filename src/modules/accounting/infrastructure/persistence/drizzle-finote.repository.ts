// src/modules/accounting/infrastructure/persistence/drizzle-finote.repository.ts
import { Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { IFinoteRepository } from '../../domain/repositories/finote.repository';
import * as schema from '@database/schema';
import { Finote } from '@modules/accounting/domain/entities/finote.entity';
import { FinoteMapper } from './mappers/finote.mapper';

@Injectable()
export class DrizzleFinoteRepository extends DrizzleBaseRepository implements IFinoteRepository {
    async save(finote: Finote): Promise<Finote> {
        const db = this.getDb();
        const data = FinoteMapper.toPersistence(finote);

        let result;
        if (data.id) {
            const [updated] = await db.update(schema.finotes)
                .set(data)
                .where(eq(schema.finotes.id, data.id))
                .returning();
            result = updated;
        } else {
            // Bỏ đoạn bóc tách { id, ...insertData }, truyền thẳng data
            const [inserted] = await db.insert(schema.finotes)
                .values(data)
                .returning();
            result = inserted;
        }

        return FinoteMapper.toDomain(result)!;
    }

    async findById(id: number): Promise<Finote | null> {
        const row = await this.getDb().query.finotes.findFirst({
            where: eq(schema.finotes.id, id),
        });
        return FinoteMapper.toDomain(row);
    }

    async addAttachment(data: any): Promise<void> {
        await this.getDb().insert(schema.finoteAttachments).values(data);
    }
}
