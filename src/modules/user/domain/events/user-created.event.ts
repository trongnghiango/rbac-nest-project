import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';
import { User } from '../entities/user.entity';

export class UserCreatedEvent implements IDomainEvent {
  static readonly EVENT_NAME = 'UserCreated';

  readonly occurredAt = new Date();
  constructor(
    public readonly aggregateId: string,
    public readonly payload: { user: User },
  ) { }
}
