// src/modules/org-structure/application/services/company-import.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { CompanyImportService } from './company-import.service';
import { IOrgStructureRepository } from '../../domain/repositories/org-structure.repository';
import { IUserAccountService } from '@modules/user/domain/ports/user-account.service.port';
import { IRbacManageService } from '@modules/rbac/domain/ports/rbac-manage.service.port';
import { IEmployeeRepository } from '@modules/employee/domain/repositories/employee.repository';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { IFileParser } from '@core/shared/application/ports/file-parser.port';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';

describe('CompanyImportService', () => {
    let service: CompanyImportService;
    let orgRepo: jest.Mocked<IOrgStructureRepository>;
    let userAccountService: jest.Mocked<IUserAccountService>;
    let fileParser: jest.Mocked<IFileParser>;
    let txManager: jest.Mocked<ITransactionManager>;

    beforeEach(async () => {
        const mockOrgRepo = {
            upsertLocations: jest.fn(),
            findLocationsByCodes: jest.fn(),
            upsertGrades: jest.fn(),
            findGradesByLevels: jest.fn(),
            upsertJobTitles: jest.fn(),
            findJobTitlesByNames: jest.fn(),
            upsertOrgUnits: jest.fn(),
            findOrgUnitsByCodes: jest.fn(),
            createPosition: jest.fn(),
            findPositionByCode: jest.fn(),
        };
        const mockUserAccountService = { 
            provisionAccount: jest.fn(),
            findByUsername: jest.fn()
        };
        const mockRbacPort = { assignRoleToUser: jest.fn() };
        const mockEmpRepo = { save: jest.fn(), findByCode: jest.fn() };
        const mockEventBus = { publish: jest.fn() };
        const mockFileParser = { parseCsvAsync: jest.fn() };
        const mockTxManager = { runInTransaction: jest.fn(cb => cb()) }; // Chạy trực tiếp callback

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                CompanyImportService,
                { provide: IOrgStructureRepository, useValue: mockOrgRepo },
                { provide: IUserAccountService, useValue: mockUserAccountService },
                { provide: IRbacManageService, useValue: mockRbacPort },
                { provide: IEmployeeRepository, useValue: mockEmpRepo },
                { provide: IEventBus, useValue: mockEventBus },
                { provide: IFileParser, useValue: mockFileParser },
                { provide: ITransactionManager, useValue: mockTxManager },
            ],
        }).compile();

        service = module.get<CompanyImportService>(CompanyImportService);
        orgRepo = module.get(IOrgStructureRepository);
        userAccountService = module.get(IUserAccountService);
        fileParser = module.get(IFileParser);
        txManager = module.get(ITransactionManager);
    });

    describe('importCoreCompany', () => {
        it('nên thực hiện quy trình import thành công hồ sơ nhân sự', async () => {
            // ARRANGE
            const adminId = 99;
            const orgId = 1;
            const buffer = Buffer.from('test');
            
            const mockRecords = [
                {
                    username: 'nghia.tn',
                    email: 'nghia@stax.vn',
                    fullName: 'Trong Nghia',
                    employeeCode: 'EMP001',
                    locationCode: 'HN',
                    departmentCode: 'TECH',
                    departmentName: 'Phòng Công Nghệ',
                    jobTitle: 'Developer',
                    gradeLevel: 1,
                    role: 'ADMIN_ROLE'
                }
            ];

            fileParser.parseCsvAsync.mockResolvedValue(mockRecords);
            orgRepo.findLocationsByCodes.mockResolvedValue([{ id: 1, code: 'HN' }]);
            orgRepo.findGradesByLevels.mockResolvedValue([{ id: 2, levelNumber: 1 }]);
            orgRepo.findJobTitlesByNames.mockResolvedValue([{ id: 3, name: 'Developer' }]);
            orgRepo.findOrgUnitsByCodes.mockResolvedValue([{ id: 10, code: 'TECH' }]);
            orgRepo.findPositionByCode.mockResolvedValue(null);
            orgRepo.createPosition.mockResolvedValue({ id: 100 } as any);
            userAccountService.findByUsername.mockResolvedValue(null);
            userAccountService.provisionAccount.mockResolvedValue({ id: 500 } as any);

            // ACT
            const result = await service.importCoreCompany(buffer, adminId, orgId);

            // ASSERT
            expect(result.success).toBe(true);
            if (result.success) {
                expect(result.stats?.employeesImported).toBe(1);
            }
            expect(userAccountService.provisionAccount).toHaveBeenCalled();
            expect(txManager.runInTransaction).toHaveBeenCalled();
        });

        it('nên trả về lỗi nếu file CSV rỗng', async () => {
            fileParser.parseCsvAsync.mockResolvedValue([]);
            const result = await service.importCoreCompany(Buffer.from(''), 1, 1);
            expect(result.success).toBe(false);
            if (!result.success) {
                expect(result.message).toContain('rỗng');
            }
        });
    });
});
