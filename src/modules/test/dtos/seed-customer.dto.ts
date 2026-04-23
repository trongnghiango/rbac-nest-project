import { IsString, IsNotEmpty, IsOptional, IsEmail } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class SeedCustomerDto {
    // Dữ liệu Organization (Thực thể Pháp nhân)
    @ApiProperty({ example: 'Công ty TNHH Giải Pháp Công Nghệ ABC', description: 'Tên công ty/khách hàng' })
    @IsString()
    @IsNotEmpty()
    companyName: string;

    @ApiPropertyOptional({ example: '0123456789', description: 'Mã số thuế' })
    @IsOptional() @IsString() taxCode?: string;

    @ApiPropertyOptional({ example: 'IT Software', description: 'Ngành nghề / Lĩnh vực' })
    @IsOptional() @IsString() industry?: string;

    @ApiPropertyOptional({ example: 'Tòa nhà Bitexco, Quận 1, TP.HCM', description: 'Địa chỉ công ty' })
    @IsOptional() @IsString() address?: string;

    @ApiPropertyOptional({ example: 'CUSTOMER', description: 'Trạng thái (PROSPECT, ACTIVE, CUSTOMER)' })
    @IsOptional() @IsString() status?: string;

    // Dữ liệu Contact (Con người liên hệ)
    @ApiProperty({ example: 'Nguyễn Văn Đối Tác', description: 'Tên người liên hệ (Được đưa vào bảng contacts)' })
    @IsString()
    @IsNotEmpty()
    contactName: string;

    @ApiPropertyOptional({ example: '0909123456', description: 'Số điện thoại cá nhân' })
    @IsOptional() @IsString() contactPhone?: string;

    @ApiPropertyOptional({ example: 'doitac@abc.com', description: 'Email cá nhân' })
    @IsOptional() @IsEmail() contactEmail?: string;

    @ApiPropertyOptional({ example: 'Giám đốc', description: 'Chức danh' })
    @IsOptional() @IsString() contactJobTitle?: string;
}
