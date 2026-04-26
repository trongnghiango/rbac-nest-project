import { ObjectDiff } from './object-diff.util';

describe('ObjectDiff', () => {
    it('should return null if there are no changes', () => {
        const obj1 = { name: 'Test', age: 25 };
        const obj2 = { name: 'Test', age: 25 };
        expect(ObjectDiff.calculate(obj1, obj2)).toBeNull();
    });

    it('should detect simple field changes', () => {
        const obj1 = { name: 'Old', age: 25 };
        const obj2 = { name: 'New', age: 25 };
        const result = ObjectDiff.calculate(obj1, obj2);
        expect(result).toEqual({
            before: { name: 'Old' },
            after: { name: 'New' }
        });
    });

    it('should exclude specified keys', () => {
        const obj1 = { name: 'Test', updatedAt: '2023-01-01' };
        const obj2 = { name: 'Test', updatedAt: '2023-01-02' };
        expect(ObjectDiff.calculate(obj1, obj2)).toBeNull();
    });

    it('should handle creation (null before)', () => {
        const obj = { name: 'New' };
        const result = ObjectDiff.calculate(null, obj);
        expect(result).toEqual({
            before: null,
            after: { name: 'New' }
        });
    });

    it('should handle deletion (null after)', () => {
        const obj = { name: 'Old' };
        const result = ObjectDiff.calculate(obj, null);
        expect(result).toEqual({
            before: { name: 'Old' },
            after: null
        });
    });

    it('should detect nested object changes', () => {
        const obj1 = { metadata: { color: 'blue' } };
        const obj2 = { metadata: { color: 'red' } };
        const result = ObjectDiff.calculate(obj1, obj2);
        expect(result).toEqual({
            before: { metadata: { color: 'blue' } },
            after: { metadata: { color: 'red' } }
        });
    });

    it('should handle dates correctly', () => {
        const d1 = new Date('2023-01-01');
        const d2 = new Date('2023-01-02');
        const obj1 = { date: d1 };
        const obj2 = { date: d2 };
        const result = ObjectDiff.calculate(obj1, obj2);
        expect(result).toEqual({
            before: { date: d1 },
            after: { date: d2 }
        });
    });
});
