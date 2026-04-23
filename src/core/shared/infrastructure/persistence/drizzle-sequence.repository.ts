// src/core/shared/infrastructure/persistence/drizzle-sequence.repository.ts
import { Injectable } from '@nestjs/common';
import { sql } from 'drizzle-orm';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { ISequenceRepository } from '../../domain/repositories/sequence.repository';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';
import { systemSequences } from '@database/schema/system/sequences.schema';

@Injectable()
export class DrizzleSequenceRepository extends DrizzleBaseRepository implements ISequenceRepository {

    async incrementAndGetNext(prefix: string): Promise<number> {
        const db = this.getDb();

        // Dùng kỹ thuật "Upsert": Nếu chưa có thì Insert = 1, nếu có rồi thì Update + 1
        const result = await db.insert(systemSequences)
            .values({
                prefix: prefix,
                currentValue: 1
            })
            .onConflictDoUpdate({
                target: systemSequences.prefix,
                set: {
                    currentValue: sql`${systemSequences.currentValue} + 1`,
                    updatedAt: new Date(),
                },
            })
            .returning({ currentValue: systemSequences.currentValue });

        return result[0].currentValue;
    }
}
