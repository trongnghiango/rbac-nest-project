// src/modules/crm/application/services/lead-intake.service.spec.ts
import { LeadIntakeService, IntelligentIntakeDto } from './lead-intake.service';
import { OrganizationStatus, OrganizationType } from '../../domain/entities/organization.entity';
import { LeadStage } from '../../domain/enums/lead-stage.enum';

describe('LeadIntakeService', () => {
    let service: LeadIntakeService;
    let mockTxManager: any;
    let mockLeadRepo: any;
    let mockOrgRepo: any;
    let mockContactRepo: any;

    beforeEach(() => {
        mockTxManager = {
            runInTransaction: jest.fn((cb) => cb()),
        };
        mockLeadRepo = {
            save: jest.fn((lead) => Promise.resolve({ id: 100, ...lead })),
        };
        mockOrgRepo = {
            save: jest.fn((org) => Promise.resolve({ id: 50, ...org })),
        };
        mockContactRepo = {
            findByPhone: jest.fn(),
            save: jest.fn((contact) => Promise.resolve({ id: 10, ...contact })),
        };

        service = new LeadIntakeService(
            mockTxManager,
            mockLeadRepo,
            mockOrgRepo,
            mockContactRepo,
        );
    });

    it('should create new Organization, Contact and Lead for a NEW customer phone', async () => {
        const dto: IntelligentIntakeDto = {
            fullName: 'Nguyễn Văn Mới',
            phone: '0988111222',
            serviceDemand: 'Thành lập công ty',
            source: 'Facebook',
        };

        // Giả lập không tìm thấy SĐT
        mockContactRepo.findByPhone.mockResolvedValue(null);

        const result = await service.intelligentIntake(dto);

        // Kiểm tra logic tạo mới
        expect(mockOrgRepo.save).toHaveBeenCalled();
        expect(mockContactRepo.save).toHaveBeenCalled();
        expect(mockLeadRepo.save).toHaveBeenCalled();
        
        expect(result.isNewCustomer).toBe(true);
        expect(result.organizationId).toBe(50);
    });

    it('should REUSE existing Organization when phone number matches existing Contact', async () => {
        const dto: IntelligentIntakeDto = {
            fullName: 'Khách Cũ Quay Lại',
            phone: '0900000000',
            serviceDemand: 'Dịch vụ Thuế',
        };

        // Giả lập tìm thấy khách cũ gắn với Org 99
        mockContactRepo.findByPhone.mockResolvedValue({
            id: 8,
            organizationId: 99,
            fullName: 'Khách Cũ',
        });

        const result = await service.intelligentIntake(dto);

        // Kiểm tra logic tái sử dụng
        expect(mockOrgRepo.save).not.toHaveBeenCalled(); // Không được tạo Org mới
        expect(mockContactRepo.save).not.toHaveBeenCalled(); // Không được tạo Contact mới
        
        expect(mockLeadRepo.save).toHaveBeenCalledWith(expect.objectContaining({
            _organizationId: 99,
            _title: 'Dịch vụ Thuế'
        }));

        expect(result.isNewCustomer).toBe(false);
        expect(result.organizationId).toBe(99);
    });

    it('should create NEW Organization if existing Contact has NO organizationId', async () => {
        const dto: IntelligentIntakeDto = {
            fullName: 'Khách Lẻ Sang Sâm',
            phone: '0888888888',
            serviceDemand: 'Tư vấn thành lập cty',
        };

        // Giả lập tìm thấy khách lẻ chưa gắn Org
        mockContactRepo.findByPhone.mockResolvedValue({
            id: 20,
            organizationId: null,
            fullName: 'Khách Lẻ',
        });

        const result = await service.intelligentIntake(dto);

        // Kiểm tra logic: Phải tạo Org mới và cập nhật Contact
        expect(mockOrgRepo.save).toHaveBeenCalled();
        expect(mockContactRepo.save).toHaveBeenCalled(); // Cần cập nhật để gắn org_id
        
        expect(result.isNewCustomer).toBe(true);
        expect(result.organizationId).toBe(50); // ID từ mockOrgRepo
    });
});
