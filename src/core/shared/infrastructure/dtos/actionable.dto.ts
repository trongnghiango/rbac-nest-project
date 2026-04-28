import { ApiProperty } from '@nestjs/swagger';

export class ActionDetailDto {
  @ApiProperty({ description: 'Liệu hành động này có được phép hay không' })
  readonly allowed: boolean;

  @ApiProperty({ description: 'Lý do nếu không được phép', required: false })
  readonly reason?: string;
}

/**
 * Standardized metadata for actionable UI components
 */
export class ActionableDto {
  @ApiProperty({ type: 'object', additionalProperties: { $ref: '#/components/schemas/ActionDetailDto' } })
  readonly _actions: Record<string, ActionDetailDto>;
}
