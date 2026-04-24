// src/modules/user/infrastructure/dtos/user-response.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { User } from '../../domain/entities/user.entity';

export class UserResponseDto {
    @ApiProperty() id: number;
    @ApiProperty() username: string;
    @ApiPropertyOptional() email?: string;
    @ApiProperty() fullName: string;
    @ApiProperty() isActive: boolean;
    @ApiProperty() roles: string[];
    @ApiPropertyOptional() telegramId?: string;

    // Chúng ta có thể cấu trúc lại object cho đẹp thay vì bê nguyên từ DB
    @ApiPropertyOptional() avatarUrl?: string;
    @ApiPropertyOptional() phoneNumber?: string;

    static fromDomain(entity: User): UserResponseDto {
        const dto = new UserResponseDto();
        dto.id = entity.id!;
        dto.username = entity.username;
        dto.email = entity.email;
        dto.fullName = entity.fullName; // Gọi get fullName() của Entity
        dto.isActive = entity.isActive;
        dto.roles = entity.roles;
        dto.telegramId = entity.telegramId;

        // Bóc phẳng (Flatten) personalInfo ra cho dễ dùng
        dto.avatarUrl = entity.personalInfo?.avatarUrl;
        dto.phoneNumber = entity.personalInfo?.phoneNumber;

        return dto;
    }
}

