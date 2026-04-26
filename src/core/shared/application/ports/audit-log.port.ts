export enum AuditLogSeverity {
    INFO = 'INFO',
    WARNING = 'WARNING',
    ERROR = 'ERROR',
    CRITICAL = 'CRITICAL'
}

export const AUDIT_LOG_PORT = Symbol('AUDIT_LOG_PORT');

export interface AuditLogEntry {
    action: string;
    resource: string;
    resourceId?: string;
    organizationId?: number;
    actorId?: string | number; // Support both
    actorName?: string;
    before?: any;
    after?: any;
    metadata?: Record<string, any>;
    severity?: AuditLogSeverity | string;
    ipAddress?: string;
    userAgent?: string;
    requestId?: string;
}

export interface IAuditLogService {
    log(entry: AuditLogEntry): Promise<void>;
    // Added for test script compatibility
    query?(filter: { action?: string; resource?: string; resourceId?: string }): Promise<any[]>;
}
