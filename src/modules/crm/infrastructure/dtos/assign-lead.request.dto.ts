import { ApiProperty } from '@nestjs/swagger';
import { IsInt, Min } from 'class-validator';

export class AssignLeadRequestDto {
  @ApiProperty({
    description: 'ID của nhân viên được gán (STAFF/MANAGER)',
    example: 2,
  })
  @IsInt()
  @Min(1)
  readonly employeeId: number;
}
