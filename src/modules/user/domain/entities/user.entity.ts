import { UserPersonalInfo, UserBusinessContext } from '../types/user-contexts.type';

export interface UserProps {
  id?: number;
  username: string;
  email?: string;
  hashedPassword?: string;
  isActive?: boolean;
  roles?: string[];
  telegramId?: string;

  // Dữ liệu Metadata (Con người)
  personalInfo?: UserPersonalInfo;

  // Ngữ cảnh nghiệp vụ (Công việc)
  profileContext?: UserBusinessContext;

  createdAt?: Date;
  updatedAt?: Date;
}

export class User {
  private _id?: number;
  private _username: string;
  private _email?: string;
  private _hashedPassword?: string;
  private _isActive: boolean;
  private _roles: string[];
  private _telegramId?: string;

  private _personalInfo: UserPersonalInfo;
  private _profileContext: UserBusinessContext;


  private _createdAt?: Date;
  private _updatedAt?: Date;

  constructor(props: UserProps) {
    this._id = props.id;
    this._username = props.username;
    this._email = props.email;
    this._hashedPassword = props.hashedPassword;
    this._telegramId = props.telegramId;

    // Sử dụng Nullish Coalescing (??) để tránh ghi đè giá trị 'false' hoặc '0'
    this._isActive = props.isActive ?? true;
    this._roles = props.roles ?? [];

    // Khởi tạo đối tượng rỗng để đảm bảo user.personalInfo.fullName không bao giờ bị crash
    this._personalInfo = props.personalInfo ?? {};
    this._profileContext = props.profileContext ?? {};

    this._createdAt = props.createdAt ?? new Date();
    this._updatedAt = props.updatedAt ?? new Date();
  }

  // --- Getters (Truy cập dữ liệu) ---
  get id() { return this._id; }
  get username() { return this._username; }
  get email() { return this._email; }
  get hashedPassword() { return this._hashedPassword; }
  get isActive() { return this._isActive; }
  get roles() { return [...this._roles]; } // Trả về bản sao để bảo vệ mảng gốc (Immutability)
  get telegramId() { return this._telegramId; }

  // ✅ [LEGACY SUPPORT] Giúp các service cũ gọi user.fullName vẫn chạy tốt
  get fullName(): string {
    return this._personalInfo.fullName ?? this._username;
  }

  get personalInfo() { return this._personalInfo; }
  get profileContext() { return this._profileContext; }

  get createdAt() { return this._createdAt; }
  get updatedAt() { return this._updatedAt; }

  // --- Domain Behaviors (Logic nghiệp vụ) ---

  /**
   * Cập nhật mật khẩu và tự động đổi updatedAt
   */
  changePassword(hashedPassword: string): void {
    if (!hashedPassword) throw new Error('Hashed password is required');
    this._hashedPassword = hashedPassword;
    this.markModified();
  }

  /**
   * Cập nhật thông tin cá nhân (Merge dữ liệu cũ và mới)
   */
  updatePersonalInfo(data: Partial<UserPersonalInfo>): void {
    this._personalInfo = { ...this._personalInfo, ...data };
    this.markModified();
  }

  deactivate(): void {
    this._isActive = false;
    this.markModified();
  }

  activate(): void {
    this._isActive = true;
    this.markModified();
  }

  /**
   * Kiểm tra quyền nhanh
   */
  hasRole(roleName: string): boolean {
    return this._roles.includes(roleName);
  }

  // --- Business Helpers (Check vai trò) ---

  // Tối ưu: Kiểm tra xem User có đang đóng vai trò nào trong hệ thống không
  isEmployee(): boolean { return !!this._profileContext.employee; }
  isOrganization(): boolean { return !!this._profileContext.organization; }
  isStudent(): boolean { return !!this._profileContext.student; }

  /**
   * Cập nhật thời gian sửa đổi cuối cùng
   */
  private markModified(): void {
    this._updatedAt = new Date();
  }

  /**
   * Xuất dữ liệu sạch cho API
   */
  toJSON() {
    return {
      id: this._id,
      username: this._username,
      email: this._email,
      fullName: this.fullName, // Phẳng hóa fullName ra ngoài cho Frontend dễ dùng
      isActive: this._isActive,
      roles: this._roles,
      telegramId: this._telegramId,
      personalInfo: this._personalInfo,
      profileContext: this._profileContext,
      createdAt: this._createdAt,
      updatedAt: this._updatedAt,
    };
  }
}
