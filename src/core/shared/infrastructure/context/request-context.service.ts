import { Injectable } from '@nestjs/common';
import { AsyncLocalStorage } from 'async_hooks';

export class RequestContext {
  constructor(
    public readonly requestId: string,
    public readonly url: string,
    public readonly ip?: string,
    public readonly userAgent?: string,
    public userId?: string | number,
    public userName?: string,
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
    return store?.requestId || 'sys-' + process.pid;
  }

  static getContext(): RequestContext | undefined {
    return this.als.getStore();
  }

  static setUserId(userId: string | number, userName?: string) {
    const store = this.als.getStore();
    if (store) {
      (store as any).userId = userId;
      if (userName) (store as any).userName = userName;
    }
  }
}
