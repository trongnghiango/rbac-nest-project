import { IDomainEvent } from './domain-event.interface';

/**
 * IAuditableEvent
 *
 * Domain event nào implement interface này sẽ được AuditDomainEventHandler
 * tự động pick up và ghi vào audit_logs mà không cần can thiệp thủ công.
 *
 * Pattern: opt-in — chỉ mark event muốn trace, tránh noise từ low-level events.
 *
 * @example
 * export class LeadStageChangedEvent implements IAuditableEvent {
 *   readonly aggregateId: string;
 *   readonly occurredAt = new Date();
 *   readonly payload: Record<string, any>;
 *
 *   toAuditEntry(): AuditEntryDto {
 *     return {
 *       action: 'LEAD.STAGE_CHANGED',
 *       resource: 'leads',
 *       resource_id: this.aggregateId,
 *       before: { stage: this.payload.oldStage },
 *       after: { stage: this.payload.newStage },
 *     };
 *   }
 * }
 */
export interface IAuditableEvent extends IDomainEvent {
    /**
     * Convert event thành AuditEntry để ghi DB.
     * Handler sẽ merge thêm actor_id, actor_ip, request_id từ request context.
     */
    toAuditEntry(): AuditEntryPayload;
}

/**
 * Partial entry — handler sẽ enrich thêm WHO context (actor_id, ip, request_id)
 */
export interface AuditEntryPayload {
    action: string;           // e.g. 'LEAD.STAGE_CHANGED'
    resource: string;         // table/entity name
    resource_id?: string;     // entity PK as string
    before?: Record<string, any> | null;
    after?: Record<string, any> | null;
    severity?: 'INFO' | 'WARN' | 'CRITICAL';
    metadata?: Record<string, any>;
}
