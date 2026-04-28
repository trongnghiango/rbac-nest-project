import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, MinLength } from 'class-validator';

export class RejectFinoteRequestDto {
  @ApiProperty({
    description: 'Lý do từ chối phiếu',
    example: 'Hồ sơ đi kèm bị thiếu thông tin hóa đơn VAT',
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(5)
  readonly reason: string;
}
