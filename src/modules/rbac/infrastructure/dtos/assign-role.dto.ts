import { ApiProperty } from '@nestjs/swagger';
import { IsNumber } from 'class-validator';

export class AssignRoleDto {
  @ApiProperty({ example: 1005, description: 'User ID' })
  @IsNumber()
  userId: number;

  @ApiProperty({ example: 2, description: 'Role ID' })
  @IsNumber()
  roleId: number;
}
