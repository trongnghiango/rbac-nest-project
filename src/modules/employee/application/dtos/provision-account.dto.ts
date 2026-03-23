import { IsString, IsEmail, IsOptional, MinLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ProvisionAccountDto {
    @ApiProperty({ description: 'Email của nhân viên để nhận thông báo', example: 'vana.nguyen@company.com' })
    @IsEmail()
    email: string;

    @ApiPropertyOptional({
        description: 'Tên đăng nhập tự chọn (Tối thiểu 4 ký tự). Nếu để trống hệ thống sẽ dùng Mã nhân viên.',
        example: 'vana.nguyen'
    })
    @IsOptional()
    @IsString()
    @MinLength(4, { message: 'Username phải có ít nhất 4 ký tự' })
    username?: string;
}
