import { PaginationRequestDto } from '../../dtos/pagination.request.dto';

export class DrizzlePaginationUtil {
  static getLimitOffset(dto: PaginationRequestDto): { limit: number; offset: number } {
    const limit = dto.limit && dto.limit > 0 ? dto.limit : 20;
    const page = dto.page && dto.page > 0 ? dto.page : 1;
    const offset = (page - 1) * limit;

    return { limit, offset };
  }
}
