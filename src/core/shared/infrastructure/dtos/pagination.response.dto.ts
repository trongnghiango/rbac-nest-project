import { ApiProperty } from '@nestjs/swagger';

export class PaginationMetaDto {
  @ApiProperty()
  readonly totalCount: number;

  @ApiProperty()
  readonly totalPages: number;

  @ApiProperty()
  readonly currentPage: number;

  @ApiProperty()
  readonly itemsPerPage: number;

  @ApiProperty()
  readonly hasNextPage: boolean;

  @ApiProperty()
  readonly hasPreviousPage: boolean;

  constructor({ totalCount, limit, page }: { totalCount: number, limit: number, page: number }) {
    this.totalCount = totalCount;
    this.itemsPerPage = limit;
    this.currentPage = page;
    this.totalPages = Math.ceil(totalCount / limit);
    this.hasNextPage = this.currentPage < this.totalPages;
    this.hasPreviousPage = this.currentPage > 1;
  }
}

export class PaginationResponseDto<T> {
  @ApiProperty({ isArray: true })
  readonly items: T[];

  @ApiProperty({ type: () => PaginationMetaDto })
  readonly meta: PaginationMetaDto;

  constructor(items: T[], meta: PaginationMetaDto) {
    this.items = items;
    this.meta = meta;
  }
}
