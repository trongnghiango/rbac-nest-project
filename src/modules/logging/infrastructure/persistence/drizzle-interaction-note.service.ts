import { Injectable, Inject } from '@nestjs/common';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE } from '@database/drizzle.provider';
import * as schema from '@database/schema';
import { 
    IInteractionNoteService, 
    InteractionNoteRecord, 
    CreateInteractionNoteCommand 
} from '@core/shared/application/ports/interaction-note.port';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { desc, eq } from 'drizzle-orm';

@Injectable()
export class DrizzleInteractionNoteService extends DrizzleBaseRepository implements IInteractionNoteService {
    constructor(
        @Inject(DRIZZLE) db: NodePgDatabase<typeof schema>,
    ) {
        super(db);
    }

    async create(command: CreateInteractionNoteCommand): Promise<InteractionNoteRecord> {
        const db = this.getDb();
        
        const [result] = await db.insert(schema.interactionNotes).values({
            organization_id: command.organization_id,
            type: command.type || 'NOTE',
            content: command.content,
            metadata: command.metadata,
        }).returning();

        return result as InteractionNoteRecord;
    }

    async findByOrganization(organization_id: number): Promise<InteractionNoteRecord[]> {
        const db = this.getDb();
        return await db.query.interactionNotes.findMany({
            where: eq(schema.interactionNotes.organization_id, organization_id),
            orderBy: [desc(schema.interactionNotes.created_at)],
        }) as InteractionNoteRecord[];
    }
}
