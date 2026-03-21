// Định nghĩa kiểu dữ liệu truyền vào (Props)
export interface SessionProps {
  id?: string;
  userId: number;
  token: string;
  refreshToken: string;
  expiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
  createdAt?: Date;
}

export class Session {
  public id?: string;
  public userId: number;
  public token: string;
  public refreshToken: string;
  public expiresAt: Date;
  public ipAddress?: string;
  public userAgent?: string;
  public createdAt?: Date;

  constructor(props: SessionProps) {
    this.id = props.id;
    this.userId = props.userId;
    this.token = props.token;
    this.refreshToken = props.refreshToken;
    this.expiresAt = props.expiresAt;
    this.ipAddress = props.ipAddress;
    this.userAgent = props.userAgent;
    this.createdAt = props.createdAt;
  }

  isExpired(): boolean {
    return new Date() > this.expiresAt;
  }
}
