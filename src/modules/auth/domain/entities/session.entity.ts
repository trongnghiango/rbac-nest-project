export class Session {
  constructor(
    public id: string | undefined, // Cho phép undefined
    public userId: number,
    public token: string,
    public expiresAt: Date,
    public ipAddress?: string,
    public userAgent?: string,
    public createdAt?: Date,
  ) {}

  isExpired(): boolean {
    return new Date() > this.expiresAt;
  }
}
