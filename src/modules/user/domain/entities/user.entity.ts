import { UserProfile } from '../types/user-profile.type';

export class User {
  constructor(
    private _id: number,
    private _username: string,
    private _email?: string,
    private _hashedPassword?: string,
    private _fullName?: string,
    private _isActive: boolean = true,
    // ✅ Strict RBAC: Role là danh sách mảng string
    private _roles: string[] = [],
    // ✅ Chatbot Integration
    private _telegramId?: string,
    private _phoneNumber?: string,
    private _avatarUrl?: string,
    private _profile?: UserProfile,
    private _createdAt?: Date,
    private _updatedAt?: Date,
  ) { }

  // --- Getters ---
  get id() { return this._id; }
  get username() { return this._username; }
  get email() { return this._email; }
  get hashedPassword() { return this._hashedPassword; }
  get fullName() { return this._fullName; }
  get isActive() { return this._isActive; }
  get roles() { return this._roles; } // Getter cho roles
  get telegramId() { return this._telegramId; } // Getter cho telegramId
  get phoneNumber() { return this._phoneNumber; }
  get avatarUrl() { return this._avatarUrl; }
  get profile() { return this._profile; }
  get createdAt() { return this._createdAt; }
  get updatedAt() { return this._updatedAt; }

  // --- Domain Behaviors ---

  // Lưu ý: ID thường được set bởi DB hoặc Service khi tạo mới, 
  // nhưng trong Entity Constructor nên có để hydrate từ DB.

  changePassword(hashedPassword: string): void {
    this._hashedPassword = hashedPassword;
    this._updatedAt = new Date();
  }

  updateProfile(profileData: UserProfile): void {
    this._profile = { ...this._profile, ...profileData };
    this._updatedAt = new Date();
  }

  deactivate(): void {
    this._isActive = false;
    this._updatedAt = new Date();
  }

  activate(): void {
    this._isActive = true;
    this._updatedAt = new Date();
  }

  // Phương thức này giúp Service/Chatbot kiểm tra nhanh quyền
  hasRole(roleName: string): boolean {
    return this._roles.includes(roleName);
  }

  toJSON() {
    return {
      id: this._id,
      username: this._username,
      email: this._email,
      fullName: this._fullName,
      isActive: this._isActive,
      roles: this._roles, // ✅ Trả về mảng roles
      telegramId: this._telegramId,
      phoneNumber: this._phoneNumber,
      avatarUrl: this._avatarUrl,
      profile: this._profile,
      createdAt: this._createdAt,
      updatedAt: this._updatedAt,
    };
  }
}
