// src/modules/accounting/application/strategies/target-resolver/target-resolver.interface.ts

export interface ITargetResolverStrategy {
    /**
     * Khai báo loại Finote mà Strategy này xử lý (VD: 'INCOME', 'EXPENSE')
     */
    supportsType(): string;

    /**
     * Hàm thực hiện logic lấy tên đối tượng
     */
    resolveTargetName(payload: any): Promise<string>;
}
