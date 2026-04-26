export const INTERACTION_NOTE_PORT = Symbol('INTERACTION_NOTE_PORT');

export interface InteractionNoteRecord {
    id: number;
    organizationId: number;
    createdById: number | null;
    type: string;
    content: string;
    metadata?: Record<string, any>;
    createdAt: Date;
    updatedAt: Date;
}

export interface CreateInteractionNoteCommand {
    organizationId: number;
    createdById?: number;
    type?: string;
    content: string;
    metadata?: Record<string, any>;
}

export interface IInteractionNoteService {
    create(command: CreateInteractionNoteCommand): Promise<InteractionNoteRecord>;
    findByOrganization(organizationId: number): Promise<InteractionNoteRecord[]>;
}
