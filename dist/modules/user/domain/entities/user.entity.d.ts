import type { UserProfile } from '../types/user-profile.type';
export declare class User {
    id: number;
    username: string;
    email?: string;
    hashedPassword?: string;
    fullName: string;
    isActive: boolean;
    phoneNumber?: string;
    avatarUrl?: string;
    profile?: UserProfile;
    createdAt: Date;
    updatedAt: Date;
    updateProfile(profileData: UserProfile): void;
    setPassword(password: string): void;
    deactivate(): void;
    activate(): void;
    toJSON(): Omit<this, "hashedPassword" | "updateProfile" | "setPassword" | "deactivate" | "activate" | "toJSON">;
}
