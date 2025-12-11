import type { UserProfile } from '../types/user-profile.type';

export class User {
  // Properties are private (Encapsulation)
  constructor(
    private _id: number | undefined,
    private _username: string,
    private _email?: string,
    private _hashedPassword?: string,
    private _fullName?: string,
    private _isActive: boolean = true,
    private _phoneNumber?: string,
    private _avatarUrl?: string,
    private _profile?: UserProfile,
    private _createdAt?: Date,
    private _updatedAt?: Date,
  ) {}

  // Getters
  get id() {
    return this._id;
  }
  get username() {
    return this._username;
  }
  get email() {
    return this._email;
  }
  get hashedPassword() {
    return this._hashedPassword;
  }
  get fullName() {
    return this._fullName;
  }
  get isActive() {
    return this._isActive;
  }
  get phoneNumber() {
    return this._phoneNumber;
  }
  get avatarUrl() {
    return this._avatarUrl;
  }
  get profile() {
    return this._profile;
  }
  get createdAt() {
    return this._createdAt;
  }
  get updatedAt() {
    return this._updatedAt;
  }

  // Business Methods (Behavior)

  // Set ID (Only used by persistence layer when creating new)
  setId(id: number) {
    if (this._id) throw new Error('ID is immutable once set');
    this._id = id;
  }

  updateProfile(profileData: UserProfile): void {
    this._profile = { ...this._profile, ...profileData };
    this._updatedAt = new Date();
  }

  changePassword(hashedPassword: string): void {
    this._hashedPassword = hashedPassword;
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

  toJSON() {
    return {
      id: this._id,
      username: this._username,
      email: this._email,
      fullName: this._fullName,
      isActive: this._isActive,
      phoneNumber: this._phoneNumber,
      avatarUrl: this._avatarUrl,
      profile: this._profile,
      createdAt: this._createdAt,
      updatedAt: this._updatedAt,
    };
  }
}
