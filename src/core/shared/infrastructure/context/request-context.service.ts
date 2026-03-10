import { Injectable } from '@nestjs/common';
import { AsyncLocalStorage } from 'async_hooks';

export class RequestContext {
  constructor(
    public readonly requestId: string,
    public readonly url: string,
  ) {}
}

@Injectable()
export class RequestContextService {
  // Static để có thể gọi ở bất cứ đâu (kể cả nơi không inject được)
  private static readonly als = new AsyncLocalStorage<RequestContext>();

  static run(context: RequestContext, callback: () => void) {
    this.als.run(context, callback);
  }

  static getRequestId(): string {
    const store = this.als.getStore();
    return store?.requestId || 'sys-' + process.pid; // Fallback nếu không có request (VD: Cronjob)
  }

  static getContext(): RequestContext | undefined {
    return this.als.getStore();
  }
}
