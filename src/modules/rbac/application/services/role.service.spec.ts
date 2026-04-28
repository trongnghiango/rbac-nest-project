import { Test, TestingModule } from '@nestjs/testing';
import { RoleService } from './role.service';
import { IRoleRepository, IPermissionRepository } from '../../domain/repositories/rbac.repository';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { ICacheService } from '@core/shared/application/ports/cache.port';

describe('RoleService', () => {
    let service: RoleService;

    const mockRoleRepo = {
        save: jest.fn(),
        findByName: jest.fn(),
    };

    const mockPermissionRepo = {
        save: jest.fn()
    };

    const mockCacheService = {
        get: jest.fn(),
        set: jest.fn()
    };

    const mockTransactionManager = {
        runInTransaction: jest.fn((cb) => cb()),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                RoleService,
                { provide: IRoleRepository, useValue: mockRoleRepo },
                { provide: IPermissionRepository, useValue: mockPermissionRepo },
                { provide: ITransactionManager, useValue: mockTransactionManager },
                { provide: ICacheService, useValue: mockCacheService },
            ],
        }).compile();

        service = module.get<RoleService>(RoleService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    it('should create a role correctly (scaffold)', async () => {
        // TODO: Implement actual test
    });
});
