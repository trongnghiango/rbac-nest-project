// src/core/constants/pg-error-codes.ts
export const PG_ERROR_CODES = {
    UNIQUE_VIOLATION: '23505',
    FOREIGN_KEY_VIOLATION: '23503',
    NOT_NULL_VIOLATION: '23502',
    CHECK_VIOLATION: '23514',
    INVALID_TEXT_REPRESENTATION: '22P02', // Sai kiểu dữ liệu (VD: truyền chuỗi vào cột UUID)
};
