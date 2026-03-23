export interface IDomainEvent {
  readonly aggregateId: string;
  readonly occurredAt: Date;
  readonly payload: Record<string, any>;
}
