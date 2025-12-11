export interface IDomainEvent {
  readonly aggregateId: string;
  readonly eventName: string;
  readonly occurredAt: Date;
  readonly payload: Record<string, any>;
}
