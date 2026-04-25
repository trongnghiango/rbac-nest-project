/**
 * IAuditLogService Port
 *
 * Theo pattern ILogger — module nào muốn inject audit chỉ cần dùng token AUDIT_LOG_PORT.
 * Implementation có thể swap: PostgreSQL → ClickHouse → Elasticsearch mà không đụng tới caller.
 */

export const AUDIT_LOG_PORT = Symbol('IAuditLogService');

export interface AuditEntryDto {
    // WHO
    actor_id?: number | null;
    actor_type?: string;
    actor_name?: string;
    actor_ip?: string;
    // WHAT
    action: string;
    resource: string;
    resource_id?: string;
    // CHANGE
    before?: Record<string, any> | null;
    after?: Record<string, any> | null;
    // CONTEXT
    request_id?: string;
    user_agent?: string;
    metadata?: Record<string, any>;
    severity?: 'INFO' | 'WARN' | 'CRITICAL';
}

export interface AuditQueryDto {
    actor_id?: number;
    resource?: string;
    resource_id?: string;
    action?: string;
    severity?: string;
    from?: Date;
    to?: Date;
    page?: number;
    limit?: number;
}

export interface AuditLogRecord extends AuditEntryDto {
    id: number;
    created_at: Date;
}

export interface PaginatedAuditResult {
    data: AuditLogRecord[];
    total: number;
    page: number;
    limit: number;
}

export interface IAuditLogService {
    /** Ghi 1 audit entry. Fire-and-forget — không throw nếu lỗi. */
    log(entry: AuditEntryDto): Promise<void>;

    /** Ghi nhiều entries trong 1 batch (cho migration, import). */
    logBatch(entries: AuditEntryDto[]): Promise<void>;

    /** Query audit history theo filter. Dùng cho UI "Lịch sử thay đổi". */
    query(filter: AuditQueryDto): Promise<PaginatedAuditResult>;
}
