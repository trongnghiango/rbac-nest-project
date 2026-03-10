import { SetMetadata } from '@nestjs/common';
import { Type } from '@nestjs/common';
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

export const EVENT_HANDLER_METADATA = 'EVENT_HANDLER_METADATA';

export const EventHandler = (event: Type<IDomainEvent> | string) =>
  SetMetadata(EVENT_HANDLER_METADATA, event);
