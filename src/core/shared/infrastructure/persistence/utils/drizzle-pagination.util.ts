export class DrizzlePaginationUtil {
  /**
   * Tính toán limit và offset cho Drizzle query
   * Đã tách biệt khỏi DTO để có thể dùng cho cả Background Jobs
   */
  static getLimitOffset(options: { page?: number; limit?: number }): { limit: number; offset: number } {
    const limit = options.limit && options.limit > 0 ? options.limit : 20;
    const page = options.page && options.page > 0 ? options.page : 1;
    const offset = (page - 1) * limit;

    return { limit, offset };
  }
}
