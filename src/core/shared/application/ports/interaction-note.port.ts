export const INTERACTION_NOTE_PORT = Symbol('INTERACTION_NOTE_PORT');

export interface InteractionNoteRecord {
    id: number;
    organization_id: number;
    created_by_id: number | null;
    type: string;
    content: string;
    metadata?: any;
    created_at: Date;
    updated_at: Date;
}

export interface CreateInteractionNoteCommand {
    organization_id: number;
    type?: string;
    content: string;
    metadata?: any;
}

export interface IInteractionNoteService {
    create(command: CreateInteractionNoteCommand): Promise<InteractionNoteRecord>;
    findByOrganization(organization_id: number): Promise<InteractionNoteRecord[]>;
}
