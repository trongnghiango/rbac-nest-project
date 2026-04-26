/**
 * Utility to calculate differences between two objects for auditing purposes.
 */
export class ObjectDiff {
    /**
     * Calculates the delta between two objects.
     * Returns an object containing the 'before' and 'after' states of ONLY changed fields.
     */
    static calculate(
        oldObj: any, 
        newObj: any, 
        excludeKeys: string[] = ['updatedAt', 'updated_at', 'deletedAt', 'deleted_at', 'password']
    ): { before: any; after: any } | null {
        if (!oldObj && !newObj) return null;
        
        // If creating (no old state)
        if (!oldObj && newObj) {
            const filteredNew = this.filterObject(newObj, excludeKeys);
            return { before: null, after: filteredNew };
        }

        // If deleting (no new state)
        if (oldObj && !newObj) {
            const filteredOld = this.filterObject(oldObj, excludeKeys);
            return { before: filteredOld, after: null };
        }

        const before: any = {};
        const after: any = {};
        let hasChange = false;

        const allKeys = new Set([...Object.keys(oldObj), ...Object.keys(newObj)]);

        for (const key of allKeys) {
            if (excludeKeys.includes(key)) continue;

            const valOld = oldObj[key];
            const valNew = newObj[key];

            // Deep comparison using stringification for simplicity in this context
            // In a more complex scenario, we'd use a deep equal algorithm
            if (this.isDifferent(valOld, valNew)) {
                before[key] = valOld === undefined ? null : valOld;
                after[key] = valNew === undefined ? null : valNew;
                hasChange = true;
            }
        }

        return hasChange ? { before, after } : null;
    }

    private static isDifferent(val1: any, val2: any): boolean {
        if (val1 === val2) return false;
        
        // Handle dates
        if (val1 instanceof Date && val2 instanceof Date) {
            return val1.getTime() !== val2.getTime();
        }

        // Handle null/undefined comparison
        if ((val1 === null || val1 === undefined) && (val2 === null || val2 === undefined)) {
            return false;
        }

        // Deep check for objects/arrays
        if (typeof val1 === 'object' || typeof val2 === 'object') {
            return JSON.stringify(val1) !== JSON.stringify(val2);
        }

        return val1 !== val2;
    }

    private static filterObject(obj: any, excludeKeys: string[]): any {
        if (!obj || typeof obj !== 'object') return obj;
        
        const result: any = {};
        for (const key in obj) {
            if (!excludeKeys.includes(key)) {
                result[key] = obj[key];
            }
        }
        return result;
    }
}
